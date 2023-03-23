#!/usr/bin/env groovy

import groovy.json.JsonSlurperClassic

import java.util.concurrent.Callable

def getSmSecret(
        String path,
        List<VaultKeyToEnvVar> keysAndValues
) {
    String expected_name = path
    String listAllResp = "{}"
    withEnv(["SM_EXPECTED_NAME=$expected_name"]) {
        listAllResp = sh(
                script: '''
                #!/bin/bash +x
                set +x
                curl -X GET --location --header "Authorization: Bearer $SM_TOKEN" \
                    --header "Accept: application/json" \
                    "$SM_URI/api/v1/secrets?search=$SM_EXPECTED_NAME"
            ''',
                returnStdout: true
        )
    }

    def listAllObj = new JsonSlurperClassic().parseText(listAllResp)
    def matchingSecretResources = listAllObj['resources'].findAll { it['name'] == expected_name }.collect()

    if (!matchingSecretResources) {
        //TODO: better Exception type?
        throw new RuntimeException("secret not found: `${path}`)")
    }
    def matchingSecret = matchingSecretResources[0]

    String secret_id = matchingSecret['id']
    String secret_type = matchingSecret['secret_type']

    String getResp = "{}"
    withEnv(["SM_SECRET_TYPE=$secret_type","SM_SECRET_ID=$secret_id"]) {
        getResp = sh(
                script: '''
                #!/bin/bash +x
                set +x
                curl -X GET --location --header "Authorization: Bearer $SM_TOKEN" \
                    --header "Accept: application/json" \
                    "$SM_URI/api/v1/secrets/$SM_SECRET_TYPE/$SM_SECRET_ID"
            ''',
                returnStdout: true
        )
    }
    def getRespObj = new JsonSlurperClassic().parseText(getResp)
    def payload = getRespObj['resources'][0]['secret_data']['payload']

    Map<String, String> secretValues = keysAndValues.collectEntries { entry ->
        [(entry.envVar): payload]
    }

    return secretValues
}

class VaultKeyToEnvVar {
    public String vaultKey
    public String envVar

    VaultKeyToEnvVar(Map<String, String> map) {
        this.envVar = map["envVar"]
        this.vaultKey = map["vaultKey"]
    }
}

def withSecretSM(
        def configuration, // Map<String, String>
        def secrets, // [[path: ..., secretValues: [[envVar: ..., vaultKey: ...]]]]
        Callable<?> fn
) {
    String credentialsId = configuration["vaultCredentialId"]
    String vaultUri = configuration["vaultUrl"]

    String token = ""
    withCredentials([string(credentialsId: credentialsId, variable: "SM_API_KEY")]) {
        String tokenResp = sh(
                script: '''
                #!/bin/bash +x
                curl -X POST "https://iam.cloud.ibm.com/identity/token" \
                  -H "Content-Type: application/x-www-form-urlencoded" \
                  -H "Accept: application/json" \
                  -d "grant_type=urn%3Aibm%3Aparams%3Aoauth%3Agrant-type%3Aapikey&apikey=$SM_API_KEY"
            ''',
                returnStdout: true
        )
        token = new JsonSlurperClassic().parseText(tokenResp)['access_token']
    }

    String prefixPath = configuration["prefixPath"]

    Map<String, String> allSecretValues = null
    withEnv(["SM_URI=$vaultUri", "SM_TOKEN=$token"]) {
        wrap([$class: "MaskPasswordsBuildWrapper",
              varPasswordPairs: [[password: SM_TOKEN]]]) {
            allSecretValues = secrets.collect {
                String fullPath = it["path"]
                //String fullPath = (prefixPath + "/" + path).replaceAll("//", "/")
                def secretValues = (it["secretValues"] as List<Map<String, String>>)
                def keysAndEnvs = secretValues.collect {
                    return new VaultKeyToEnvVar(it)
                }
                return getSmSecret(fullPath, keysAndEnvs)
            }.collectEntries()
        }
    }

    List<String> envVars = allSecretValues.collect { entry ->
        return "${entry.key}=${entry.value}".toString()
    }
    List<Map<String, String>> varPasswordPairs = allSecretValues.collect { entry ->
        return [password: entry.value, var: entry.key]
    }

    withEnv(envVars) {
        wrap([$class: "MaskPasswordsBuildWrapper", varPasswordPairs: varPasswordPairs]) {
            fn()
        }
    }
}

/**
 * Secret extraction supporting Secrets Manager while also mostly compatible with Vault plugin.
 *
 * It uses SOS Vault or Secrets Manager variant depending on vaultUrl. For SOS Vault it falls back to `withVault`,
 * so it should support all of its features. For Secrets Manager, there are a few notable differences:
 *  * `vaultCredentialId` only supports `string` type Jenkins secrets, which contain the Secrets Manager API key
 *  * no support for `vaultCredential`
 *  * due to Secrets Manager always using K/V engine kv2, the `engineVersion` option is ignored
 *  * `timeout` option is not supported yet
 *  * `vaultNamespace` is not supported
 *  * always fails if not found, regardless of the value of `failIfNotFound` option
 *
 * @param options - map containing `configuration` and `vaultSecrets`. There is also an overload variant with those two
 * as positional arguments.
 * @param fn - closure to use
 * @return nothing
 */
def withSecret(Map<String, ?> options, Callable<?> fn) {
    return withSecret(options["configuration"], options["vaultSecrets"], fn)
}


def call(Map<String, ?> options) {
    echo "test"
}

/**
 * Variant with `configuration` and `secretValues` being separate.
 */
def withSecret(
        def configuration, // Map<String, String>
        def vaultSecrets // [[path: ..., secretValues: [[envVar: ..., vaultKey: ...]]]]
) {
    String serviceUrl = configuration["vaultUrl"]
    if (serviceUrl == "") {
        //TODO: better error type
        throw new RuntimeException("no `serviceUrl` defined for `configuration` in `withSecret`")
    }

    Boolean isSecretsManager = serviceUrl.contains("secrets-manager.appdomain.cloud")

    // SOS Vault or SecretsManager
    if (!isSecretsManager) {
        withVault([configuration: configuration, vaultSecrets: vaultSecrets]) {
            
        }
    } else {
        withSecretSM(configuration, vaultSecrets, fn)
    }
}
