#include <sys/process.h>
#include "common.h"
#include <time.h>
#include <tiny3d.h>
#include <libfont2.h>
#include <libfont.h>
#include "ttf_render.h"
#include <stdio.h>
#include "font.h"

void load_texture() {
    u32 * texture_mem = tiny3d_AllocTexture(170*1024*1024); 
    u32 * texture_pointer;
    if(!texture_mem) return; //whomp
    texture_pointer = texture_mem;
    ResetFont();
    texture_pointer = (u32 *) AddFontFromBitmapArray((u8 *) font  , (u8 *) texture_pointer, 32, 255, 16, 32, 2, BIT0_FIRST_PIXEL);

    // {
    //     TTFLoadFont(1, "/dev_flash/data/font/SCE-PS3-RD-L-LATIN.TTF", NULL, 0);
    // }
    // texture_mem = (u32 *) texture_pointer;
    // if(!texture_mem) return;
    // texture_pointer += 1024 * 16;
    // texture_pointer = (u32 *) init_ttf_table((u16 *) texture_pointer);
}

int num_digits(int n) {
    if (n == 0) return 1; // 0 has 1 digit
    int count = 0;
    if (n < 0) n = -n;    // handle negative numbers
    while (n > 0) {
        n /= 10;
        count++;
    }
    return count;
}

int get_temp(int proc, uint32_t *temp) {
	//0 - cell
	//1 - rsx
	//14 - southbridge?
	lv2syscall2(383, proc, (uint64_t) temp);
	return_to_user_prog(int);
}

float get_fan_speed(uint8_t *fan_speed, uint8_t *fan_policy) {
    uint8_t status, policy, speed, duty;

    lv2syscall5(409, 0, (uint64_t)&status, (uint64_t)&policy, (uint64_t) &speed, (uint64_t)&duty);
    
	*fan_speed = speed * 100.0 / 255.0;
    //1 - syscon
    //2 - auto
    *fan_policy = policy;
    return_to_user_prog(int);
}

int get_software_version() {
    lv2syscall0(376);

    return_to_user_prog(int);
}

void get_time_string(char* buffer, size_t size) {
    uint64_t secs = 0, nsecs = 0;
    int timezone, summertime = 0;
    
    {
        lv2syscall2(145, (u64)&secs, (u64)&nsecs); //time in seconds
    }
    {
        lv2syscall2(144, &timezone, &summertime); //timezone info
    }
    
    int localized = (timezone + summertime);
    secs += (int64_t)localized * 60;

    struct tm timeinfo;
    gmtime_r((time_t*)&secs, &timeinfo);

    snprintf(buffer, size, "%02d:%02d:%02d",
             timeinfo.tm_hour,
             timeinfo.tm_min,
             timeinfo.tm_sec);
}