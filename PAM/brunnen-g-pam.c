/* pam_brunnen_g.c - PAM module for Brunnen-G authentication */

#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <curl/curl.h>
#include <json-c/json.h>

#define BRUNNEN_API_URL "http://localhost:8080/api/v1"
#define MAX_RESPONSE_SIZE 4096

struct response_data {
    char *data;
    size_t size;
};

static size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    struct response_data *mem = (struct response_data *)userp;
    
    char *ptr = realloc(mem->data, mem->size + realsize + 1);
    if (!ptr) return 0;
    
    mem->data = ptr;
    memcpy(&(mem->data[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->data[mem->size] = 0;
    
    return realsize;
}

static int verify_brunnen_identity(const char *username, const char *password) {
    CURL *curl;
    CURLcode res;
    struct response_data response = {0};
    int ret = PAM_AUTH_ERR;
    
    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();
    
    if (!curl) return PAM_AUTH_ERR;
    
    // Build API URL
    char url[512];
    snprintf(url, sizeof(url), "%s/verify?address=%s", BRUNNEN_API_URL, username);
    
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&response);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
    
    res = curl_easy_perform(curl);
    
    if (res == CURLE_OK) {
        // Parse JSON response
        struct json_object *parsed_json;
        struct json_object *verified;
        
        parsed_json = json_tokener_parse(response.data);
        if (parsed_json) {
            if (json_object_object_get_ex(parsed_json, "verified", &verified)) {
                if (json_object_get_boolean(verified)) {
                    ret = PAM_SUCCESS;
                }
            }
            json_object_put(parsed_json);
        }
    }
    
    free(response.data);
    curl_easy_cleanup(curl);
    curl_global_cleanup();
    
    return ret;
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    const char *username;
    const char *password;
    int ret;
    
    // Get username
    ret = pam_get_user(pamh, &username, "Brunnen-G Username: ");
    if (ret != PAM_SUCCESS || !username) {
        return PAM_AUTH_ERR;
    }
    
    // Get password (or challenge response)
    ret = pam_get_authtok(pamh, PAM_AUTHTOK, &password, "YubiKey OTP: ");
    if (ret != PAM_SUCCESS) {
        return PAM_AUTH_ERR;
    }
    
    // Verify with Brunnen-G
    return verify_brunnen_identity(username, password);
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_SERVICE_ERR;
}