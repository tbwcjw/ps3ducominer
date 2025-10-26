#ifndef STRUCT_H
#define STRUCT_H

#include <stdint.h>
#include <signal.h>

#include <sys/mutex.h>
#include <sys/cond.h>
#include <sys/thread.h>

#include <pthread.h>

typedef struct {
    int server_fd;
    int client_fd;
    pthread_t wd_thread;
    int wd_thread_created;
} WebDashboard;


typedef struct {
    float total_hashrate;                                   ///< combined hashrate (kH/s)
    int total_difficulty;                                   ///< combined difficulty
    float avg_difficulty;                                   ///< average difficulty
    int total_shares;                                       ///< shares submitted
    int good_shares;                                        ///< shares accepted
    int bad_shares;                                         ///< shares rejected
    int blocks;                                             ///< blocks found
} MiningResults;

typedef struct {
    int socket_fd;
    sys_ppu_thread_t thread_id;
    float hashrate;
    int difficulty;
    int good_shares;
    int bad_shares;
    int blocks;
    char* error; 
    sig_atomic_t stop_mining;

} ThreadData;

typedef struct {
    int last_share;
    int total_shares;
    uint8_t fan_speed;
    uint8_t fan_policy;
    uint32_t cell_temp;
    uint32_t rsx_temp;
    pthread_t* mining_threads;                              ///< array of mining threads
    ThreadData* thread_data;                                ///< array of thread-specific data
    int single_miner_id;                                    ///< single id for all threads, to display as a single device in wallet
    sig_atomic_t pause_mining;
    WebDashboard* web_dashboard;
} ResourceManager;

typedef struct {
    char* node;
    int port;
    char* name;
    char* wallet_address;
    char* miner_key;
    char* difficulty;
    char* rig_id;
    bool iot;
    int threads;
    bool web_dashboard;
} MiningConfig;
#endif

struct MemoryStruct {
    char* memory;                                           ///< ptr to allocated memory
    size_t size;                                            ///< size of allocated memory
};