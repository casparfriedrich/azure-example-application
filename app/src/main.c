#include <zephyr/posix/time.h>

#include <cJSON.h>
#include <cJSON_os.h>
#include <device.h>
#include <easy_azure.h>
#include <easy_wifi.h>
#include <init.h>
#include <logging/log.h>
#include <net/sntp.h>
#include <net/tls_credentials.h>
#include <sys/reboot.h>
#include <zephyr.h>

LOG_MODULE_REGISTER(app, LOG_LEVEL_DBG);

#define PSK  ""
#define SSID ""

#define NTP_HOST       "pool.ntp.org"
#define NTP_TIMEOUT_MS 5000
#define NTP_PRECISION  10000000000

#define AZ_SEC_TAG CONFIG_EASY_AZURE_SEC_TAG

#define DEVICE_IDX 0

static const char server_ca[] = "-----BEGIN CERTIFICATE-----\r\n"
				"...\r\n"
				"R9I4LtD+gdwyah617jzV/OeBHRnDJELqYzmp\r\n"
				"-----END CERTIFICATE-----\r\n";
static const char device_crt[] = "-----BEGIN CERTIFICATE-----\r\n"
				 "...\r\n"
				 "R9I4LtD+gdwyah617jzV/OeBHRnDJELqYzmp\r\n"
				 "-----END CERTIFICATE-----\r\n";
static const char device_key[] = "-----BEGIN EC PRIVATE KEY-----\r\n"
				 "...\r\n"
				 "R9I4LtD+gdwyah617jzV/OeBHRnDJELqYzmp\r\n"
				 "-----END EC PRIVATE KEY-----\r\n";
static const char device_id[] = "...";

static unsigned int counter = 0;

time_t time(time_t *tloc)
{
	struct timespec ts;
	int ret;

	ret = clock_gettime(CLOCK_REALTIME, &ts);
	if (ret < 0) {
		return ret;
	}

	if (tloc) {
		*tloc = ts.tv_sec;
	}

	return ts.tv_sec;
}

static int add_credentials(void)
{
	int ret;

	ret = tls_credential_add(AZ_SEC_TAG, TLS_CREDENTIAL_CA_CERTIFICATE, server_ca,
				 sizeof(server_ca));
	if (ret) {
		LOG_WRN("Failed to register ca certificate: %d", ret);
	}

	ret = tls_credential_add(AZ_SEC_TAG, TLS_CREDENTIAL_SERVER_CERTIFICATE, device_crt,
				 sizeof(device_crt));
	if (ret) {
		LOG_WRN("Failed to register device certificate: %d", ret);
	}

	ret = tls_credential_add(AZ_SEC_TAG, TLS_CREDENTIAL_PRIVATE_KEY, device_key,
				 sizeof(device_key));
	if (ret) {
		LOG_WRN("Failed to register device key: %d", ret);
	}

	return 0;
}

void main(void)
{
	int ret;

	cJSON *msg = NULL;
	cJSON *msg_device_id = NULL;
	cJSON *msg_counter = NULL;

	cJSON_Init();

	msg = cJSON_CreateObject();
	if (!msg) {
		LOG_WRN("cJSON_CreateObject failed");
	}

	msg_device_id = cJSON_CreateString(device_id);
	if (!msg_device_id) {
		LOG_WRN("cJSON_CreateString failed");
	}
	cJSON_AddItemToObject(msg, "device_id", msg_device_id);

	msg_counter = cJSON_CreateNumber(0);
	if (!msg_counter) {
		LOG_WRN("cJSON_CreateNumber failed");
	}
	cJSON_AddItemToObject(msg, "counter", msg_counter);

	ret = add_credentials();
	__ASSERT(!ret, "add_credentials failed: %d", ret);

	while (true) {
		ret = easy_wifi_connect(SSID, PSK, K_SECONDS(30));
		if (ret && ret != -EALREADY) {
			LOG_ERR("easy_wifi_connect failed: %d", ret);
			goto sleep;
		}

		ret = easy_azure_connect(device_id);
		if (ret) {
			LOG_ERR("easy_azure_connect failed: %d", ret);
			goto sleep;
		}

		// ---

		cJSON_SetIntValue(msg_counter, counter++);

		char *msg_str = cJSON_PrintUnformatted(msg);
		if (!msg_str) {
			LOG_ERR("cJSON_PrintUnformatted failed");
			goto sleep;
		}

		LOG_HEXDUMP_DBG(msg_str, strlen(msg_str), "msg_str");

		ret = easy_azure_send_message(msg_str, strlen(msg_str));
		if (ret) {
			LOG_WRN("easy_azure_send_message failed: %d", ret);
		}

		cJSON_FreeString(msg_str);

		// ---

	sleep:
		ret = easy_azure_disconnect();
		if (ret) {
			LOG_WRN("easy_azure_disconnect failed: %d", ret);
		}

		ret = easy_wifi_disconnect(K_SECONDS(30));
		if (ret) {
			LOG_WRN("easy_wifi_disconnect failed: %d", ret);
		}

		k_sleep(K_SECONDS(30));
	}

	cJSON_Delete(msg);
}
