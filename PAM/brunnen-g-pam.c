#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <curl/curl.h>
#include <json-c/json.h>
#include <syslog.h>

#define DEFAULT_API_URL "http://localhost:8080/api/v1"
#define CONFIG_FILE "/etc/brunnen/pam.conf"

// Function declarations
static char* get_api_url(int argc, const char **argv);
static char* discover_mesh_api(void);
static int test_api_connectivity(const char *api_url);

// Get API URL from various sources (priority order)
static char* get_api_url(int argc, const char **argv) {
    char *api_url = NULL;
    FILE *config_file;
    char line[512];
    
    // 1. Check PAM module arguments first
    for (int i = 0; i < argc; i++) {
        if (strncmp(argv[i], "api_url=", 8) == 0) {
            api_url = strdup(argv[i] + 8);
            syslog(LOG_DEBUG, "pam_brunnen: Using API URL from PAM args: %s", api_url);
            return api_url;
        }
    }
    
    // 2. Check environment variable
    char *env_url = getenv("BRUNNEN_API_URL");
    if (env_url) {
        api_url = strdup(env_url);
        syslog(LOG_DEBUG, "pam_brunnen: Using API URL from environment: %s", api_url);
        return api_url;
    }
    
    // 3. Check configuration file
    config_file = fopen(CONFIG_FILE, "r");
    if (config_file) {
        while (fgets(line, sizeof(line), config_file)) {
            if (strncmp(line, "api_url=", 8) == 0) {
                // Remove newline and extract URL
                char *url_start = line + 8;
                char *newline = strchr(url_start, '\n');
                if (newline) *newline = '\0';
                api_url = strdup(url_start);
                syslog(LOG_DEBUG, "pam_brunnen: Using API URL from config: %s", api_url);
                break;
            }
        }
        fclose(config_file);
        if (api_url) return api_url;
    }
    
    // 4. Try mesh discovery
    api_url = discover_mesh_api();
    if (api_url) {
        syslog(LOG_DEBUG, "pam_brunnen: Using API URL from mesh discovery: %s", api_url);
        return api_url;
    }
    
    // 5. Fall back to default
    api_url = strdup(DEFAULT_API_URL);
    syslog(LOG_DEBUG, "pam_brunnen: Using default API URL: %s", api_url);
    return api_url;
}

// Discover API via Yggdrasil mesh network
static char* discover_mesh_api(void) {
    FILE *fp;
    char *api_url = NULL;
    char ygg_addr[256];
    
    // Get local Yggdrasil address
    fp = popen("yggdrasilctl getSelf 2>/dev/null | grep -oE '200:[a-f0-9:]+'", "r");
    if (fp) {
        if (fgets(ygg_addr, sizeof(ygg_addr), fp)) {
            // Remove newline
            char *newline = strchr(ygg_addr, '\n');
            if (newline) *newline = '\0';
            
            // Try local mesh API
            api_url = malloc(256);
            snprintf(api_url, 256, "http://[%s]:8080/api/v1", ygg_addr);
            
            // Test if API is reachable
            if (test_api_connectivity(api_url)) {
                pclose(fp);
                return api_url;
            }
            free(api_url);
            api_url = NULL;
        }
        pclose(fp);
    }
    
    // Try discovering peers via blockchain registry
    fp = popen("emercoin-cli name_filter 'registry:node-' 2>/dev/null", "r");
    if (fp) {
        char line[1024];
        while (fgets(line, sizeof(line), fp)) {
            // Parse registry entries for API endpoints
            // Extract Yggdrasil addresses and try them
            // This would need JSON parsing of registry entries
        }
        pclose(fp);
    }
    
    return NULL;
}

// Test API connectivity with quick health check
static int test_api_connectivity(const char *api_url) {
    CURL *curl;
    CURLcode res;
    char health_url[512];
    long response_code;
    
    curl = curl_easy_init();
    if (!curl) return 0;
    
    snprintf(health_url, sizeof(health_url), "%s/../health", api_url);
    
    curl_easy_setopt(curl, CURLOPT_URL, health_url);
    curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);  // HEAD request
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 2L); // Quick timeout
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    
    res = curl_easy_perform(curl);
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
    curl_easy_cleanup(curl);
    
    return (res == CURLE_OK && response_code == 200);
}
#define MAX_RESPONSE_SIZE 4096

struct api_response {
    char *data;
    size_t size;
};

// Callback function to write HTTP response data
static size_t write_callback(void *contents, size_t size, size_t nmemb, struct api_response *response) {
    size_t total_size = size * nmemb;
    
    response->data = realloc(response->data, response->size + total_size + 1);
    if (response->data == NULL) {
        return 0;
    }
    
    memcpy(&(response->data[response->size]), contents, total_size);
    response->size += total_size;
    response->data[response->size] = 0;
    
    return total_size;
}

// Query Brunnen-G API to verify user identity
static int verify_user_identity(const char *username, const char *api_base_url) {
    CURL *curl;
    CURLcode res;
    struct api_response response = {0};
    char url[512];
    int auth_result = PAM_AUTH_ERR;
    
    curl = curl_easy_init();
    if (!curl) {
        syslog(LOG_ERR, "pam_brunnen: Failed to initialize curl");
        return PAM_AUTH_ERR;
    }
    
    // Build query URL with dynamic base
    snprintf(url, sizeof(url), "%s/query?address=%s", api_base_url, username);
    
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
    
    res = curl_easy_perform(curl);
    
    if (res == CURLE_OK) {
        long response_code;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
        
        if (response_code == 200) {
            // Parse JSON response
            json_object *root = json_tokener_parse(response.data);
            if (root) {
                json_object *status_obj;
                if (json_object_object_get_ex(root, "status", &status_obj)) {
                    const char *status = json_object_get_string(status_obj);
                    if (strcmp(status, "success") == 0) {
                        auth_result = PAM_SUCCESS;
                        syslog(LOG_INFO, "pam_brunnen: User %s verified via TPM identity", username);
                    }
                }
                json_object_put(root);
            }
        } else if (response_code == 404) {
            auth_result = PAM_USER_UNKNOWN;
            syslog(LOG_WARNING, "pam_brunnen: User %s not found in blockchain", username);
        }
    } else {
        syslog(LOG_ERR, "pam_brunnen: API request failed: %s", curl_easy_strerror(res));
    }
    
    if (response.data) {
        free(response.data);
    }
    curl_easy_cleanup(curl);
    
    return auth_result;
}

// Trigger TPM challenge-response authentication
static int trigger_tpm_auth(pam_handle_t *pamh, const char *username) {
    char command[256];
    int result;
    
    // Execute TPM authentication script
    snprintf(command, sizeof(command), "/usr/local/bin/brunnen-cli.sh authenticate-user '%s'", username);
    
    result = system(command);
    if (WEXITSTATUS(result) == 0) {
        pam_info(pamh, "TPM authentication successful for %s", username);
        return PAM_SUCCESS;
    } else {
        pam_error(pamh, "TPM authentication failed for %s", username);
        return PAM_AUTH_ERR;
    }
}

// Main PAM authentication function
PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    const char *username;
    char *api_url;
    int retval;
    
    // Get dynamic API URL
    api_url = get_api_url(argc, argv);
    if (!api_url) {
        syslog(LOG_ERR, "pam_brunnen: Failed to determine API URL");
        return PAM_AUTH_ERR;
    }
    
    // Get username from PAM
    retval = pam_get_user(pamh, &username, "Brunnen-G Identity: ");
    if (retval != PAM_SUCCESS) {
        syslog(LOG_ERR, "pam_brunnen: Failed to get username");
        free(api_url);
        return retval;
    }
    
    // Check if username follows Brunnen-G format (user@domain.coin)
    if (!strchr(username, '@') || !strstr(username, ".coin")) {
        syslog(LOG_WARNING, "pam_brunnen: Invalid identity format: %s", username);
        free(api_url);
        return PAM_USER_UNKNOWN;
    }
    
    // Step 1: Verify user exists in blockchain
    retval = verify_user_identity(username, api_url);
    if (retval != PAM_SUCCESS) {
        free(api_url);
        return retval;
    }
    
    // Step 2: Trigger TPM + YubiKey authentication
    retval = trigger_tpm_auth(pamh, username);
    if (retval != PAM_SUCCESS) {
        free(api_url);
        return retval;
    }
    
    syslog(LOG_INFO, "pam_brunnen: Authentication successful for %s via %s", username, api_url);
    free(api_url);
    return PAM_SUCCESS;
}

// PAM account management (check if account is valid)
PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    const char *username;
    char *api_url;
    int retval;
    
    retval = pam_get_user(pamh, &username, NULL);
    if (retval != PAM_SUCCESS) {
        return retval;
    }
    
    // Get dynamic API URL
    api_url = get_api_url(argc, argv);
    if (!api_url) {
        return PAM_AUTH_ERR;
    }
    
    // Re-verify user identity for account management
    retval = verify_user_identity(username, api_url);
    free(api_url);
    
    return retval;
}

// PAM session management
PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    const char *username;
    
    if (pam_get_user(pamh, &username, NULL) == PAM_SUCCESS) {
        syslog(LOG_INFO, "pam_brunnen: Session opened for %s", username);
    }
    
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    const char *username;
    
    if (pam_get_user(pamh, &username, NULL) == PAM_SUCCESS) {
        syslog(LOG_INFO, "pam_brunnen: Session closed for %s", username);
    }
    
    return PAM_SUCCESS;
}

// PAM password management (not used in Brunnen-G)
PAM_EXTERN int pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    // Brunnen-G uses hardware authentication, no password changes
    return PAM_SUCCESS;
}