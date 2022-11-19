#ifndef EASY_AZURE_H
#define EASY_AZURE_H

#include <stdint.h>
#include <stdlib.h>

int easy_azure_connect(const char *device_id);
int easy_azure_disconnect(void);

#ifdef CONFIG_EASY_AZURE_D2C_MESSAGES
int easy_azure_send_message(const uint8_t *message, size_t message_len);
#endif // CONFIG_EASY_AZURE_D2C_MESSAGES

#endif // EASY_AZURE_H
