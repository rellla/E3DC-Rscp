#ifndef __E3DC_CONFIG_H_
#define __E3DC_CONFIG_H_

#include "RscpTypes.h"

#define CONF_FILE "/etc/e3dc.conf"

#define ARGBUF              4096
#define AES_KEY_SIZE        32
#define AES_BLOCK_SIZE      32
#define MAX_CONN_RETRY      3
#define MAX_AUTH_RETRY      3

typedef struct {
    char server_ip[20];
    int  server_port;
    char e3dc_user[128];
    char e3dc_password[128];
    char aes_password[128];
}e3dc_config_t;

typedef struct {
    uint8_t hour;
    uint8_t minute;
}idle_time_t;

typedef struct {
    uint8_t type;
    uint8_t day;
    uint8_t active;
    idle_time_t start;
    idle_time_t stop;
}idle_period_t;

#define MONDAY			0
#define TUESDAY			1
#define WEDNESDAY		2
#define THURSDAY		3
#define FRIDAY			4
#define SATURDAY		5
#define SUNDAY			6

#define INACTIVE		0
#define ACTIVE			1

#define LOAD			0
#define UNLOAD			1

#define TAG_BATTERY		(1 << 0)
#define TAG_EMS			(1 << 1)
#define TAG_GET_IDLE_PERIODS	(1 << 2)
#define TAG_WEATHER_ENABLE	(1 << 3)
#define TAG_WEATHER_ENABLE_F	(1 << 4)
#define TAG_SET_IDLE_PERIODS	(1 << 5)

#endif
