#include <string.h>
#include <stdio.h>
#include <stdarg.h>

#include <ppu-lv2.h>
#include <sys/thread.h>
#include <pthread.h>
#include <sys/process.h>
#include <io/pad.h>

#include <sysutil/msg.h>
#include <sysutil/sysutil.h>

#include <sys/socket.h>
#include <arpa/inet.h>
#include <curl/curl.h>
#include <netdb.h>
#include <time.h>
#include <polarssl/sha1.h>

#include <rsx/gcm_sys.h>
#include <ppu-types.h>

#include <tiny3d.h>
#include <libfont2.h>
#include "font.h"

#include "dashboard.h"
#include "jsmn.h"
#include "struct.h"
#include "common.h"
#include "debug.h"

#include <errno.h>

#define CONFIG_FILE "/dev_hdd0/tmp/ps3ducominer.txt"
#define GET_POOL "http://server.duinocoin.com/getPool" //<not https plox

#define SOFTWARE "ps3ducominer"
#define CURL_USERAGENT "psl1ght curl ps3ducominer"

#define DUCO_ORANGE 0xFC6803FF
#define ERROR_RED   0xFF0000FF 
#define NOTICE_BLUE 0x87CEEBFF 
#define DARK_GREY   0x5A5A5AFF 
#define LIGHT_GREY  0x878787FF 
#define WHITE       0xFFFFFFFF
#define BLACK       0x00000000

#define FONT_X 12
#define FONT_Y 12
#define LINE_PADDING 2
#define LINE_HEIGHT (FONT_Y + 2 * LINE_PADDING)

#define NEXT_LINE(sy, line_num) ((sy) + (line_num) * LINE_HEIGHT)

WebDashboard web = {
    .server_fd = -1,
    .client_fd = -1,
    .wd_thread = {0},
    .wd_thread_created = 0
};

ResourceManager res = {
    .mining_threads = NULL,
    .thread_data = NULL,
    .single_miner_id = 0,
    .web_dashboard = &web,
    .pause_mining = 0,
};

MiningConfig mc = {
    .node = NULL,
    .port = 0,
    .name = NULL,
    .difficulty = NULL,
    .rig_id = NULL,
    .iot = false,
    .wallet_address = NULL,
    .miner_key = NULL,
    .threads = 0,
    .web_dashboard = false
};

MiningResults mr = {0};

vs32 dialog_action = 0;
void dialog_handle(msgButton button, void *userdata) {
    switch(button)
    {
        case MSG_DIALOG_BTN_YES:
            dialog_action = 1;
            break;
        case MSG_DIALOG_BTN_NO:
        case MSG_DIALOG_BTN_ESCAPE:
        case MSG_DIALOG_BTN_NONE:
            dialog_action = 2;
            break;
        default:
            break;
    }
}

vs32 exit_dialog() {
    netDebug("launching exit confirmation dialog");
    msgType dialogType = (msgType)(MSG_DIALOG_NORMAL | MSG_DIALOG_BTN_TYPE_YESNO | MSG_DIALOG_DEFAULT_CURSOR_NO);
    msgDialogOpen2(dialogType,"Are you sure you want to exit?",dialog_handle,NULL,NULL);

    dialog_action = 0;
	while(!dialog_action) {
        tiny3d_Flip();
    }
    return dialog_action;
}

int cleanup(char* fmt, ...) {
    netDebug("cleanup() called");
    char buffer[256] = {0};

    if (fmt != NULL) {
        va_list args;
        va_start(args, fmt);
        vsnprintf(buffer, sizeof(buffer), fmt, args);
        va_end(args);
    }

    //netDebug("cleanup() called: %s", buffer);
    if (fmt != NULL) { //error dialog
        netDebug("launching error dialog");
        msgType dialogType = (msgType)(MSG_DIALOG_ERROR | MSG_DIALOG_BTN_TYPE_OK | MSG_DIALOG_DISABLE_CANCEL_ON);
        msgDialogOpen2(dialogType,buffer,dialog_handle,NULL,NULL);

        dialog_action = 0;
        while(!dialog_action) {
            //sysUtilCheckCallback();
            tiny3d_Flip();
        }
    }
    pthread_t invalid_thread = {0};
    if (res.mining_threads)
    {
        for (int i = 0; i < mc.threads; i++)
        {
            if (!pthread_equal(res.mining_threads[i], invalid_thread)) //if thread
            {
                netDebug("Thread is open, closing");
                res.thread_data[i].stop_mining = 1; //send signal
                if (res.thread_data[i].socket_fd >= 0) //close socket
                {
                    netDebug("Closing socket");
                    shutdown(res.thread_data[i].socket_fd, SHUT_RDWR);
                    close(res.thread_data[i].socket_fd);
                    res.thread_data[i].socket_fd = -1;
                }
                netDebug("Closing and joining thread");
                //close thread
                pthread_cancel(res.mining_threads[i]); 
                pthread_join(res.mining_threads[i], NULL);
            }
        }
    }
    //close web_dashboard
    if (mc.web_dashboard && res.web_dashboard->wd_thread_created != 0) {
        netDebug("Closing web dashboard");
        if(res.web_dashboard->client_fd >= 0) close(res.web_dashboard->client_fd);
        if(res.web_dashboard->server_fd >= 0) close(res.web_dashboard->server_fd);
        pthread_cancel(res.web_dashboard->wd_thread);
        pthread_join(res.web_dashboard->wd_thread, NULL);
        free(res.web_dashboard);
    }
    netDebug("exiting...");
    #ifdef PS3LOADX
    sysProcessExitSpawn2("/dev_hdd0/game/PSL145310/RELOAD.SELF", NULL, NULL, NULL, 0, 1001, SYS_PROCESS_SPAWN_STACK_SIZE_1M);
    #endif
    return 0;
}

void set_dynamic_string(char** field, const char* value) {
    free(*field);
    *field = strdup(value);
    if (*field == NULL) {
        cleanup("An error occurred while setting up the application from config file.");
    }
}

static size_t write_memory_callback(void* contents, size_t size, size_t nmemb, void* userp) {
    size_t realsize = size * nmemb;
    struct MemoryStruct* mem = (struct MemoryStruct*)userp;

    char* ptr = realloc(mem->memory, mem->size + realsize + 1);
    if (!ptr) {
        free(mem->memory);
        mem->memory = NULL;
        mem->size = 0;
        return 0;
    }

    mem->memory = ptr;
    memcpy(&(mem->memory[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->memory[mem->size] = 0;

    return realsize;
}

void get_node(char** ip, int* port, char** name) {
    netDebug("finding node from getPool");
    CURL* curl;
    CURLcode res;

    char* json_copy = NULL;
    struct MemoryStruct chunk;
    chunk.memory = malloc(1);  // start with empty buffer
    chunk.size = 0;

    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();

    if (!curl) {
        cleanup("Failed to initialize cURL");
    }

    curl_easy_setopt(curl, CURLOPT_URL, GET_POOL);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, CURL_USERAGENT);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_memory_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void*)&chunk);

    res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        curl_easy_cleanup(curl);
        cleanup("cURL operation failed with error: %s", curl_easy_strerror(res));
    }

    curl_easy_cleanup(curl);
    json_copy = strdup(chunk.memory);
    if (!json_copy) {
        curl_easy_cleanup(curl);
        free(chunk.memory);
        cleanup("Memory allocation failed while duplicating JSON response.");
    }

    jsmn_parser parser;
    jsmntok_t tokens[13];
    jsmn_init(&parser);

    int ret = jsmn_parse(&parser, json_copy, strlen(json_copy), tokens, 13);
    if (ret < 0) {
        if(json_copy) free(json_copy);
        if(chunk.memory) free(chunk.memory);
        curl_easy_cleanup(curl);
        cleanup("Failed to parse JSON from getPool.");
    }

    for (int i = 1; i < ret; i++) {
        if (tokens[i].type == JSMN_STRING) {
            if (strncmp(json_copy + tokens[i].start, "ip", tokens[i].end - tokens[i].start) == 0) {
                if (i + 1 < ret) {
                    char ip_str[16];
                    int length = tokens[i + 1].end - tokens[i + 1].start;
                    strncpy(ip_str, json_copy + tokens[i + 1].start, length);
                    *ip = malloc(length + 1);
                    strncpy(*ip, json_copy + tokens[i + 1].start, length);
                    (*ip)[length] = '\0';
                    i++;
                }
            }
            if (strncmp(json_copy + tokens[i].start, "port", tokens[i].end - tokens[i].start) == 0) {
                if (i + 1 < ret) {
                    char port_str[16];
                    int length = tokens[i + 1].end - tokens[i + 1].start;
                    strncpy(port_str, json_copy + tokens[i + 1].start, length);
                    port_str[length] = '\0';
                    *port = atoi(port_str);
                    i++;
                }
            }
            if (strncmp(json_copy + tokens[i].start, "name", tokens[i].end - tokens[i].start) == 0) {
                if (i + 1 < ret) {
                    char name_str[32];
                    int length = tokens[i + 1].end - tokens[i + 1].start;
                    strncpy(name_str, json_copy + tokens[i + 1].start, length);
                    *name = malloc(length + 1);
                    strncpy(*name, json_copy + tokens[i + 1].start, length);
                    (*name)[length] = '\0';
                    i++;
                }
            }
        } else {
            if(json_copy) free(json_copy);
            if(chunk.memory) free(chunk.memory);
            cleanup("Failed to retrieve node information from the server");
        }
    }
    
    if(chunk.memory) free(chunk.memory);
    if(json_copy) free(json_copy);
}

void parse_config_file(MiningConfig* config) {
    printf("Reading %s\n", CONFIG_FILE);
    FILE* file = fopen(CONFIG_FILE, "r");
    if (file == NULL) {     //file doesnt exist
        netDebug("config file not found. creating it, will go to cleanup after.");

        file = fopen(CONFIG_FILE, "w"); //create file
        if (file == NULL) {
            cleanup("Failed to create the config file at %s.", CONFIG_FILE);
        }
        fprintf(file, "node:\n");
        fprintf(file, "port:\n");
        fprintf(file, "wallet_address:\n");
        fprintf(file, "miner_key:\n");
        fprintf(file, "difficulty:LOW\n"); //default to recommended
        fprintf(file, "rig_id:ps3ducominer\n"); //default to something nice
        fprintf(file, "threads:1\n"); //single threaded recommended
        fprintf(file, "web_dashboard:\n");
        fprintf(file, "iot:false"); //default false
        fclose(file);
        cleanup("A config file was created at %s. Please set values and restart the application.", CONFIG_FILE);
    }

    char line[100];
    while (fgets(line, sizeof(line), file) != NULL) {
        line[strcspn(line, "\r\n")] = '\0';
        char* sep = strchr(line, ':');
        if (!sep) continue;

        *sep = '\0';
        char* key = line;
        char* value = sep + 1;

        while (*value == ' ') value++;

        netDebug("%s:%s", key, value);

        if (strcmp(key, "node") == 0) {
            set_dynamic_string(&config->node, value);
        }
        else if (strcmp(key, "port") == 0) {
            config->port = atoi(value);
        }
        else if (strcmp(key, "wallet_address") == 0) {
            if (strlen(value) < 1) {
                cleanup("The value of 'wallet_address:' was not set correctly (in the config file).");
            }
            set_dynamic_string(&config->wallet_address, value);
        }
        else if (strcmp(key, "miner_key") == 0) { //value optional no testing
            set_dynamic_string(&config->miner_key, value);
        }
        else if (strcmp(key, "difficulty") == 0) {
            if (strlen(value) < 1) {
                cleanup("The value of 'difficulty:' was not set correctly (in the config file). The recommended value is LOW.");
            }
            set_dynamic_string(&config->difficulty, value);
        }
        else if (strcmp(key, "rig_id") == 0) {
            if (strlen(value) < 1) {
                set_dynamic_string(&config->rig_id, SOFTWARE); //default
            } else {
                set_dynamic_string(&config->rig_id, value);
            }
        }
        else if (strcmp(key, "threads") == 0) {
            config->threads = atoi(value);
            if (config->threads < 1 || config->threads > 3) { //3 thread max?
                cleanup("The value of 'threads:' was not set correctly (in the config file). Must be between 1-3.");
            }
        }
        else if (strcmp(key, "web_dashboard") == 0) {
            if (strlen(value) < 1)
                cleanup("The value of 'web_dashboard:' was not set correctly (in the config file). Must be either true or false.");
            config->web_dashboard = (strcmp(value, "true") == 0) ? true : false;
        }
        else if (strcmp(key, "iot") == 0) {
            if (strlen(value) < 1)
                cleanup("The value of 'iot:' was not set correctly (in the config file). Must be either true or false.");
            config->iot = (strcmp(value, "true") == 0) ? true : false;
        }
    }
    fclose(file);
    netDebug("Config file parsing completed");
}

void replace_placeholder(char** str, const char* placeholder, const char* value) {
    if (!str || !*str || !placeholder || !value) return;

    char* current = *str;
    size_t placeholder_len = strlen(placeholder);
    size_t value_len = strlen(value);

    size_t new_len = strlen(current) + 1;
    char* result = malloc(new_len);
    strcpy(result, current);

    char* pos;
    while ((pos = strstr(result, placeholder)) != NULL) {
        size_t prefix_len = pos - result;
        size_t suffix_len = strlen(pos + placeholder_len);
        new_len = prefix_len + value_len + suffix_len + 1;

        char* new_result = realloc(result, new_len);
        if (!new_result) {
            free(result);
            return;
        }
        result = new_result;
        pos = result + prefix_len;

        memmove(pos + value_len, pos + placeholder_len, suffix_len + 1);
        memcpy(pos, value, value_len);
    }

    free(*str);
    *str = result;
}

void* web_dashboard(void* arg) {
    pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);
    pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);

    struct sockaddr_in address = { 0 };
    int addrlen = sizeof(address);

    if ((res.web_dashboard->server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        netDebug("socket");
        cleanup("Could not create the socket for web dashboard.");
    }

    u8 opt = 1;
    setsockopt(res.web_dashboard->server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(8080);

    if (bind(res.web_dashboard->server_fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
        netDebug("bind fail");
        cleanup("The web dashboard failed to bind to the socket.");
    }

    if (listen(res.web_dashboard->server_fd, 3) < 0) {
        netDebug("listen fail");
        cleanup("The web dashboard failed to initialize its server.");
    }

    while (1) {
        pthread_testcancel();
        sched_yield();

        res.web_dashboard->client_fd = accept(res.web_dashboard->server_fd, (struct sockaddr*)&address, (socklen_t*)&addrlen);
        if (res.web_dashboard->client_fd < 0) {
            if (errno == EWOULDBLOCK || errno == EAGAIN) {
                sched_yield();
                continue;
            }
            else {
                break;
            }
        }

        char* template = strdup(html);
        if (!template) return NULL;

        char device_buf[64];
        char version_buf[6];
        char threads_buf[12];
        char hashrate_buf[64];
        char diff_buf[64];
        char shares_buf[64];
        char celltemp_buff[12];
        char rsxtemp_buff[11];
        char fanspeed_buff[16];

        snprintf(device_buf, sizeof(device_buf), "Playstation 3");
        snprintf(version_buf, sizeof(version_buf), "%.2f", get_software_version() / 10000.0);
        snprintf(hashrate_buf, sizeof(hashrate_buf), "%.2f", mr.total_hashrate);
        snprintf(diff_buf, sizeof(diff_buf), "%d", (int)mr.avg_difficulty);
        snprintf(shares_buf, sizeof(shares_buf), "%d",res.total_shares);
        snprintf(celltemp_buff, sizeof(celltemp_buff), "CELL: %d*C", (res.cell_temp >> 24));
        snprintf(rsxtemp_buff, sizeof(rsxtemp_buff), "RSX: %d*C", (res.rsx_temp >> 24));
        snprintf(fanspeed_buff, sizeof(fanspeed_buff), "FAN SPEED: %u%%", res.fan_speed);
        snprintf(threads_buf, sizeof(threads_buf), "%i", mc.threads);

        replace_placeholder(&template, "@@DEVICE@@", device_buf);
        replace_placeholder(&template, "@@DEVICE_VERSION@@", version_buf);
        replace_placeholder(&template, "@@HASHRATE@@", hashrate_buf);
        replace_placeholder(&template, "@@DIFF@@", diff_buf);
        replace_placeholder(&template, "@@SHARES@@", shares_buf);
        replace_placeholder(&template, "@@NODE@@", mc.node);
        replace_placeholder(&template, "@@ID@@", mc.rig_id);
        replace_placeholder(&template, "@@VERSION@@", VERSION);
        replace_placeholder(&template, "@@CELLTEMP@@", celltemp_buff);
        replace_placeholder(&template, "@@RSXTEMP@@", rsxtemp_buff);
        replace_placeholder(&template, "@@FANSPEED@@", fanspeed_buff);
        replace_placeholder(&template, "@@THREADS@@", threads_buf);

        send(res.web_dashboard->client_fd, template, strlen(template), 0);
        free(template);
        close(res.web_dashboard->client_fd);
    }
    return NULL;
}

//hash[0]   =           0xAB            10101011    input
//hash[0]   rshift      4       0xA     a           HIGH nibble
//hash[0]   bwise&      0xF     0xB     b           LOW  nibble
//                                      ab          result
void unrolled_hash(const uint8_t hash[20], char result_hash[41]) { //my favorite kind of hash.
    static const char hex_digits[] = "0123456789abcdef";
    result_hash[0]  = hex_digits[(hash[0] >> 4) & 0xF];
    result_hash[1]  = hex_digits[hash[0] & 0xF];
    result_hash[2]  = hex_digits[(hash[1] >> 4) & 0xF];
    result_hash[3]  = hex_digits[hash[1] & 0xF];
    result_hash[4]  = hex_digits[(hash[2] >> 4) & 0xF];
    result_hash[5]  = hex_digits[hash[2] & 0xF];
    result_hash[6]  = hex_digits[(hash[3] >> 4) & 0xF];
    result_hash[7]  = hex_digits[hash[3] & 0xF];
    result_hash[8]  = hex_digits[(hash[4] >> 4) & 0xF];
    result_hash[9]  = hex_digits[hash[4] & 0xF];
    result_hash[10] = hex_digits[(hash[5] >> 4) & 0xF];
    result_hash[11] = hex_digits[hash[5] & 0xF];
    result_hash[12] = hex_digits[(hash[6] >> 4) & 0xF];
    result_hash[13] = hex_digits[hash[6] & 0xF];
    result_hash[14] = hex_digits[(hash[7] >> 4) & 0xF];
    result_hash[15] = hex_digits[hash[7] & 0xF];
    result_hash[16] = hex_digits[(hash[8] >> 4) & 0xF];
    result_hash[17] = hex_digits[hash[8] & 0xF];
    result_hash[18] = hex_digits[(hash[9] >> 4) & 0xF];
    result_hash[19] = hex_digits[hash[9] & 0xF];
    result_hash[20] = hex_digits[(hash[10] >> 4) & 0xF];
    result_hash[21] = hex_digits[hash[10] & 0xF];
    result_hash[22] = hex_digits[(hash[11] >> 4) & 0xF];
    result_hash[23] = hex_digits[hash[11] & 0xF];
    result_hash[24] = hex_digits[(hash[12] >> 4) & 0xF];
    result_hash[25] = hex_digits[hash[12] & 0xF];
    result_hash[26] = hex_digits[(hash[13] >> 4) & 0xF];
    result_hash[27] = hex_digits[hash[13] & 0xF];
    result_hash[28] = hex_digits[(hash[14] >> 4) & 0xF];
    result_hash[29] = hex_digits[hash[14] & 0xF];
    result_hash[30] = hex_digits[(hash[15] >> 4) & 0xF];
    result_hash[31] = hex_digits[hash[15] & 0xF];
    result_hash[32] = hex_digits[(hash[16] >> 4) & 0xF];
    result_hash[33] = hex_digits[hash[16] & 0xF];
    result_hash[34] = hex_digits[(hash[17] >> 4) & 0xF];
    result_hash[35] = hex_digits[hash[17] & 0xF];
    result_hash[36] = hex_digits[(hash[18] >> 4) & 0xF];
    result_hash[37] = hex_digits[hash[18] & 0xF];
    result_hash[38] = hex_digits[(hash[19] >> 4) & 0xF];
    result_hash[39] = hex_digits[hash[19] & 0xF];
    result_hash[40] = '\0'; 
}

void* do_mining_work(void *arg) {
    pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);
    pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);

    ThreadData* td = (ThreadData*)arg;
    char recv_buf[1024];

    while(!td->stop_mining) {
        pthread_testcancel();
        reconnect: {
            td->error = NULL;
            int s = socket(AF_INET, SOCK_STREAM, 0);
            if (s < 0) { 
                td->error = "Socket creation failed";
                td->socket_fd = -1;
                sleep(1);
                continue;
            }
            else {
                td->socket_fd = s;
            }

            struct hostent* server = gethostbyname(mc.node);
            if (!server) {
                td->error = "No such host";
                close(td->socket_fd);
                sleep(1);
                continue;
            }

            struct sockaddr_in serv_addr;
            memset(&serv_addr, 0, sizeof(serv_addr));
            serv_addr.sin_family = AF_INET;
            serv_addr.sin_port = htons(mc.port);
            memcpy(&serv_addr.sin_addr.s_addr, server->h_addr, server->h_length);

            if (connect(td->socket_fd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
                td->error = "Failed to connect to host";
                close(td->socket_fd);
                sleep(1);
                continue;
            }
            read(td->socket_fd, recv_buf, sizeof(4)); //server version, we do nothing with this.
            td->error = NULL; //we've reconnected, clear errors.
            while (!td->stop_mining) {
                pthread_testcancel();
                // request job
                char job_request[128];
                if (mc.iot && td->thread_id == 0) { //only send iot information on one thread
                    char iot[36];
                    snprintf(iot, sizeof(iot), "CELL:%u*C@RSX:%u*C@Fan Speed:%u%%", (res.cell_temp >> 24), (res.rsx_temp >> 24), res.fan_speed);
                    snprintf(job_request, sizeof(job_request),
                        "JOB,%s,%s,%s,%s",
                        mc.wallet_address, mc.difficulty, mc.miner_key, iot);
                }
                else {
                    snprintf(job_request, sizeof(job_request),
                        "JOB,%s,%s,%s",
                        mc.wallet_address, mc.difficulty, mc.miner_key);
                }

                int write_job = write(td->socket_fd, job_request, strlen(job_request));
                if (write_job <= 0) {
                    td->error = "Failed to send job request.";
                    goto reconnect;     //failed to send job request
                }

                // receive job
                memset(recv_buf, 0, 1024);
                int read_job = read(td->socket_fd, recv_buf, 1024 - 1);
                if (read_job <= 0) {
                    td->error = "Failed to receive job from the node.";
                    goto reconnect;     //failed to send job request
                }

                // split job parts
                char* job_parts[3];
                char* saveptr;
                char* token = strtok_r(recv_buf, ",", &saveptr);
                for (int i = 0; i < 3 && token; i++) {
                    job_parts[i] = token;
                    token = strtok_r(NULL, ",", &saveptr);
                }

                int difficulty = atoi(job_parts[2]);
                char base_str[128];
                char expected_hash[41];
                strcpy(base_str, job_parts[0]);
                strcpy(expected_hash, job_parts[1]);

                // initialize sha1 context
                sha1_context base_ctx;
                sha1_context temp_ctx;
                sha1_starts(&base_ctx);
                sha1_update(&base_ctx, (const unsigned char*)base_str, strlen(base_str));

                time_t start_time = time(NULL);
                char result_hash[41];
                int nonce;
                for (nonce = 0; nonce <= (100 * difficulty + 1); nonce++) {
                    pthread_testcancel();
                    if ((nonce & 0x4FF) == 0) {         //every 1023 iters yield thread
                        sched_yield();
                        sysUtilCheckCallback();         //check xmb status, on open, set res.pause_mining
                        while(res.pause_mining == 1) {
                            sched_yield();                  //yield thread and check for callback until closed.
                            sysUtilCheckCallback();
                        }
                    }
                    

                    unsigned char hash[20];
                    char result_str[16];

                    temp_ctx = base_ctx;  // copy base_ctx to temp_ctx
                    int len = sprintf(result_str, "%d", nonce);
                    sha1_update(&temp_ctx, (const unsigned char*)result_str, len);
                    sha1_finish(&temp_ctx, hash);

                    // compare hash
                    unrolled_hash(hash, result_hash);

                    if (memcmp(result_hash, expected_hash, 20) == 0) {
                        double elapsed = difftime(time(NULL), start_time);
                        double hashrate = nonce / (elapsed > 0 ? elapsed : 1);

                        // send result
                        char submit_buf[64];
                        int len = snprintf(submit_buf, sizeof(submit_buf), "%d,%.2f,%s,%s,,%i",
                            nonce, hashrate, SOFTWARE, mc.rig_id, res.single_miner_id);
                        int write_result = write(td->socket_fd, submit_buf, len);

                        if (write_result <= 0) {
                            td->error = "Failed to send job result to the node.";
                            goto reconnect;      //failed to send job result
                        }
                        // read response
                        int read_result = read(td->socket_fd, recv_buf, 1024 - 1);
                        if(read_result <= 0) {
                            td->error = "Failed to receive job feedback from the node.";
                            goto reconnect;        //failed to recieve job result feedback
                        }

                        if (strncmp(recv_buf, "GOOD", 4) == 0) {
                            td->good_shares++;
                        }
                        else if (strncmp(recv_buf, "BLOCK", 5) == 0) {
                            td->blocks++;
                        }
                        else {
                            td->bad_shares++;
                        }

                        res.last_share = nonce;
                        td->difficulty = difficulty;
                        td->hashrate = hashrate / 1000.0f;
                        res.total_shares++;

                        netDebug("%i: hr: %.2fkH/s, shares: %i, diff: %i", td->thread_id, td->hashrate, res.total_shares, td->difficulty);

                        break;
                    }
                }
                td->error = NULL;
            }
        }
    }

    return 0;
}

void draw_tree_item(uint32_t color, uint32_t ncolor, int sy, char* fmt, ...) {
    char tree[4];
    sprintf(tree, "|_ ");

    char buffer[96];
    if (fmt != NULL) {
        va_list args;
        va_start(args, fmt);
        vsnprintf(buffer, sizeof(buffer), fmt, args);
        va_end(args);
    }

    SetFontColor(color, BLACK);
    DrawString(0,sy,tree);
    SetFontColor(ncolor, BLACK);
    DrawString(30,sy,buffer);
}

void draw_ordered_tree_item(uint32_t color, uint32_t ncolor, int sy, int header, char* fmt, ...) {
    char tree[4];
    if (header != -1) {
        snprintf(tree, sizeof(tree), "%d|_", header);
    } else {
        snprintf(tree, sizeof(tree), " |_");
    }

    char buffer[96];
    buffer[0] = '\0';

    if (fmt != NULL) {
        va_list args;
        va_start(args, fmt);
        vsnprintf(buffer, sizeof(buffer), fmt, args);
        va_end(args);
    }

    int ox = 30 + 10 * num_digits(header);
    SetFontColor(color, BLACK);
    DrawString(0, sy, tree);
    SetFontColor(ncolor, BLACK);
    DrawString(ox, sy, buffer);
}


void draw_logo() {
    SetFontColor(DUCO_ORANGE, BLACK);
    DrawString(480, NEXT_LINE(0, 0),    "          ##########          ");
    DrawString(480, NEXT_LINE(0, 1),    "      ##################      ");
    DrawString(480, NEXT_LINE(0, 2),    "    ######################    ");
    DrawString(480, NEXT_LINE(0, 3),    "   #######         ########   ");
    DrawString(480, NEXT_LINE(0, 4),    "  ###############    #######  ");
    DrawString(480, NEXT_LINE(0, 5),    " #########       ###   ###### ");
    DrawString(480, NEXT_LINE(0, 6),    " ##############   ##   ###### ");
    DrawString(480, NEXT_LINE(0, 7),    " ##############   ##   ###### ");
    DrawString(480, NEXT_LINE(0, 8),    " #########       ###   ###### ");
    DrawString(480, NEXT_LINE(0, 9),    "  ###############    #######  ");
    DrawString(480, NEXT_LINE(0, 10),   "   #######         ########   ");
    DrawString(480, NEXT_LINE(0, 11),   "    ######################    ");
    DrawString(480, NEXT_LINE(0, 12),   "      ##################      ");
    DrawString(480, NEXT_LINE(0, 13),   "          ##########          ");
    SetFontColor(LIGHT_GREY, BLACK);
    DrawString(480, NEXT_LINE(0, 14),   "github.com/tbwcjw/ps3ducominer");
}

void xmb_event(u64 status, u64 param, void *userdata) {
    res.pause_mining = (status == SYSUTIL_DRAW_BEGIN || status == SYSUTIL_MENU_OPEN);
}


int main(int argc, const char* argv[]) {
    patch_prot_checks();
    sysUtilRegisterCallback (0, xmb_event, NULL);

    tiny3d_Init (1024*1024);
    tiny3d_Project2D();
    load_texture();

    ioPadInit(7);
    padInfo padinfo;
	padData paddata;
    memset(&paddata, 0, sizeof(paddata));
    int pad_alive=0;

    SetCurrentFont(0);
    SetFontSize (FONT_X, FONT_Y);
    SetFontColor (WHITE, BLACK);
    SetFontAutoCenter(0);

    netDebugInit();
    netDebug("Hello!");

    parse_config_file(&mc);

    res.mining_threads = malloc(mc.threads * sizeof(pthread_t));
    res.thread_data = malloc(mc.threads * sizeof(ThreadData));
    res.single_miner_id = rand() % 2812;

    if (!res.mining_threads || !res.thread_data) {
        cleanup("Failed to allocate memory for the mining threads.");
    }

    if (mc.node == NULL || mc.port == 0) {
        get_node(&mc.node, &mc.port, &mc.name);
    }

    //create web dashboard thread
    if (mc.web_dashboard) {
        res.web_dashboard = malloc(sizeof(WebDashboard));
        if (pthread_create(&res.web_dashboard->wd_thread, NULL, web_dashboard, (void*)res.web_dashboard) != 0) {
            cleanup("Failed to create the web dashboard thread.");
        }
        res.web_dashboard->wd_thread_created = 1;
    }

    //create mining threads
    for (int i=0;i<mc.threads;i++) {
        res.thread_data[i].thread_id = i;
        if(pthread_create(&res.mining_threads[i], NULL, do_mining_work, (void*)&res.thread_data[i]) != 0) {
            cleanup("Failed to create mining thread #%i.", i);
        }
    }
    time_t last_update = 0;
    int exit_requested = 0;

    //make these into proper memory values
    char node[28];
    char timestr[34];
    char fanspeed[27];
    char temps[23];
    char diff[22];
    char hashrate[22];
    char rig_id[256];
    char totalshares[30];
    char lastshare[28];
    char percentage[65];
    char blocks[27];
    char numthreads[13];
    char thread_lines[mc.threads][4][106]; //1 per buffer, 4 lines (3+1 lb), 256 size
    while(!exit_requested) { //appletmainloop equiv
        tiny3d_Clear(0xff000000, TINY3D_CLEAR_ALL);

        //handle pad data
        pad_alive = 0;
        ioPadGetInfo(&padinfo);
        if(padinfo.status[0])  { //is there any reason to poll the other connected pads? probs not.
            ioPadGetData(0, &paddata);
            pad_alive = 1;
        }
        if(pad_alive && paddata.BTN_CIRCLE) {
            netDebug("exit disalog spawned");
            if(1 == exit_dialog()) {
                DrawString(0,0,"Waiting for threads to join..."); //this is a pseudo-error. it will only ever display long enough to see if there has been an error or the system is bogged down.
                tiny3d_Flip();
                exit_requested = 1;
                break;
            }
        }

        time_t current_time;
        time(&current_time);

        //create our strings
        if (difftime(current_time, last_update) >= 2) {
            last_update = current_time;
            //calculate aggregate scores actross threads
            mr.avg_difficulty = 0;
            mr.total_hashrate = 0;
            mr.total_difficulty = 0;
            mr.good_shares = 0;
            mr.bad_shares = 0;
            mr.blocks = 0;
            for (int i=0;i<mc.threads;i++) {
                mr.total_hashrate += res.thread_data[i].hashrate;
                mr.total_difficulty += res.thread_data[i].difficulty;
                mr.good_shares += res.thread_data[i].good_shares;
                mr.bad_shares += res.thread_data[i].bad_shares;
                mr.blocks += res.thread_data[i].blocks;
            }
            mr.avg_difficulty = (float)mr.total_difficulty / mc.threads;
            //build our strings
            if(mc.name != NULL) {
                sprintf(node, "Node: %s", mc.name);
            } else {
                sprintf(node, "Node: %s:%i", mc.node, mc.port);
            }
            

            char timebuf[256];
            get_time_string(timebuf, sizeof(timebuf));
            sprintf(timestr, "Current Time: %s",  timebuf);

            get_fan_speed(&res.fan_speed, &res.fan_policy);
            sprintf(fanspeed, "Fan Speed: %u%% (Mode %u)", res.fan_speed, res.fan_policy);

            get_temp(0, &res.cell_temp);
            get_temp(1, &res.rsx_temp);

            sprintf(temps, "CELL: %d*C RSX: %d*C", (res.cell_temp >> 24), (res.rsx_temp >> 24));
            sprintf(diff, "Difficulty: %d",  (int)mr.avg_difficulty);
            sprintf(hashrate, "Hashrate: %.2fkH/s",  mr.total_hashrate);
            sprintf(rig_id, "Rig ID: %s", mc.rig_id);
            sprintf(totalshares, "Total Shares: %i",  res.total_shares);
            sprintf(lastshare, "Last Share: %i", res.last_share);
            sprintf(percentage, "Accepted: %i/%i Rejected",
            mr.good_shares,
            mr.bad_shares
            );
            sprintf(blocks, "Blocks Found: %i",  mr.blocks);
            sprintf(numthreads, "Threads (%i)", mc.threads);

            //blocks of strings for each thread
            for (int i = 0; i < mc.threads; i++) {
                snprintf(thread_lines[i][0], sizeof(thread_lines[i][0]),
                        "Hashrate: %.2fkH/s", res.thread_data[i].hashrate);

                snprintf(thread_lines[i][1], sizeof(thread_lines[i][1]),
                        "Difficulty: %d", res.thread_data[i].difficulty);

                snprintf(thread_lines[i][2], sizeof(thread_lines[i][2]),
                        "Accepted: %i/%i Rejected",
                        res.thread_data[i].good_shares,
                        res.thread_data[i].bad_shares);
                snprintf(thread_lines[i][3], sizeof(thread_lines[i][3]),
                        " |");
            }
        }
        //draw our strings, outside of 2 second loop
        DrawString(0,NEXT_LINE(0, 0),node);
        DrawString(0,NEXT_LINE(0, 1),timestr);
        DrawString(0,NEXT_LINE(0, 2),""); // linebreak
        DrawString(0,NEXT_LINE(0, 3),fanspeed);
        DrawString(0,NEXT_LINE(0, 4),temps);
        DrawString(0,NEXT_LINE(0, 5),""); //linebreak
        DrawString(0,NEXT_LINE(0, 6),diff);
        DrawString(0,NEXT_LINE(0, 7),hashrate);
        DrawString(0,NEXT_LINE(0, 8),""); //linebreak
        DrawString(0,NEXT_LINE(0, 9),rig_id);
        DrawString(0,NEXT_LINE(0, 10),""); //linebreak
        DrawString(0,NEXT_LINE(0, 11),"Shares");

        draw_tree_item(LIGHT_GREY, WHITE, NEXT_LINE(0, 12), totalshares);
        draw_tree_item(LIGHT_GREY, WHITE, NEXT_LINE(0, 13), lastshare);
        draw_tree_item(LIGHT_GREY, WHITE, NEXT_LINE(0, 14), percentage);
        draw_tree_item(LIGHT_GREY, WHITE, NEXT_LINE(0, 15), blocks);
        DrawString(0,NEXT_LINE(0, 16),""); 

        DrawString(0, NEXT_LINE(0, 17), numthreads);

        for (int i = 0; i < mc.threads; i++) {
            char* error = res.thread_data[i].error;
            int sy = NEXT_LINE(0, 18) + i * (LINE_HEIGHT * 4);


            draw_ordered_tree_item(LIGHT_GREY, WHITE, NEXT_LINE(sy, 0), i, thread_lines[i][0]);
            draw_ordered_tree_item(LIGHT_GREY, WHITE, NEXT_LINE(sy, 1), -1, thread_lines[i][1]);
            draw_ordered_tree_item(LIGHT_GREY, WHITE, NEXT_LINE(sy, 2), -1, thread_lines[i][2]);

            if (error != NULL) {
                draw_ordered_tree_item(ERROR_RED, ERROR_RED, NEXT_LINE(sy, 3), -1, "ERROR: %s", error);
                SetFontColor(WHITE, BLACK);
            }
            
            else if (i != mc.threads-1){
                SetFontColor(LIGHT_GREY, BLACK);
                DrawString(0, NEXT_LINE(sy, 3), " | ");
                SetFontColor(WHITE, BLACK);
            }
        }
        //logo
        draw_logo();

        //exit helper   
        SetFontColor(NOTICE_BLUE, BLACK);
        DrawFormatString(0, 512, "Press CIRCLE to exit...");

        //version string x.xx
        SetFontColor(DARK_GREY, BLACK);
        DrawFormatString(680, 512, "Version %s", VERSION);
        SetFontColor(WHITE, BLACK);
        tiny3d_Flip();
    }

    cleanup(NULL);
    return 0;
}