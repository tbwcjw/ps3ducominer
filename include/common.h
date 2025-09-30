#ifndef COMMON_H
#define COMMON_H

#include <stdint.h>  // for uint32_t

void patch_prot_checks();
float get_fan_speed(uint8_t *fan_speed, uint8_t *fan_policy);
int get_temp(int proc, uint32_t *temp);
void get_time_string(char* buffer, size_t size);
void load_texture();
int get_software_version();
int num_digits(int n);
#endif