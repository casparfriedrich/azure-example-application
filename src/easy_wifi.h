#ifndef EASY_WIFI_H
#define EASY_WIFI_H

#include <zephyr/device.h>

int easy_wifi_connect(const char *ssid, const char *psk, k_timeout_t timeout);
int easy_wifi_disconnect(k_timeout_t timeout);

#endif // EASY_WIFI_H
