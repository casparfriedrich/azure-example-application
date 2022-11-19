#include "easy_azure.h"

#include <errno.h>
#include <stdio.h>

#include <azure/az_iot.h>
#include <drivers/hwinfo.h>
#include <init.h>
#include <logging/log.h>
#include <net/mqtt.h>
#include <net/socket.h>
#include <net/tls_credentials.h>
#include <random/rand32.h>

#define HOST CONFIG_EASY_AZURE_IOT_HUB_CNAME
#define PORT STRINGIFY(AZ_IOT_DEFAULT_MQTT_CONNECT_PORT)

// Todo: Make configurable
#define CLIENT_ID_MAX_LEN  64
#define USER_NAME_MAX_LEN  256
#define MQTT_BUF_SIZE	   KB(2)
#define MQTT_TOPIC_MAX_LEN 64

LOG_MODULE_REGISTER(easy_azure, LOG_LEVEL_DBG);

K_MUTEX_DEFINE(api_lock);

static struct mqtt_client mqtt_client;
static az_iot_hub_client iot_hub_client;

static struct k_poll_signal mqtt_connack_sig = K_POLL_SIGNAL_INITIALIZER(mqtt_connack_sig);
static struct k_poll_signal mqtt_disconnect_sig = K_POLL_SIGNAL_INITIALIZER(mqtt_disconnect_sig);
static struct k_poll_signal mqtt_puback_sig = K_POLL_SIGNAL_INITIALIZER(mqtt_puback_sig);
static struct k_poll_signal mqtt_suback_sig = K_POLL_SIGNAL_INITIALIZER(mqtt_suback_sig);
static struct k_poll_signal twin_received_sig = K_POLL_SIGNAL_INITIALIZER(twin_received_sig);

static struct k_poll_event message_sent_events[] = {
	K_POLL_EVENT_STATIC_INITIALIZER(K_POLL_TYPE_SIGNAL, K_POLL_MODE_NOTIFY_ONLY,
					&mqtt_puback_sig, 0),
};

static int dns_lookup_internal(void)
{
	static const struct addrinfo addrinfo_hints = {
		.ai_family = AF_INET,
		.ai_socktype = SOCK_STREAM,
		.ai_protocol = IPPROTO_IP,
	};

	static struct addrinfo *addrinfo;

	int ret;

	freeaddrinfo(addrinfo);

	mqtt_client.broker = NULL;

	ret = getaddrinfo(HOST, PORT, &addrinfo_hints, &addrinfo);
	if (ret) {
		LOG_ERR("getaddrinfo failed: %d", ret);
		return ret;
	}

	mqtt_client.broker = addrinfo->ai_addr;

	return 0;
}

static int dns_lookup(void)
{
	int ret;
	int ret_lookup;

	ret = sys_mutex_lock(&mqtt_client.internal.mutex, K_FOREVER);
	if (ret) {
		LOG_ERR("sys_mutex_lock failed: %d", ret);
		return ret;
	}

	ret_lookup = dns_lookup_internal();

	ret = sys_mutex_unlock(&mqtt_client.internal.mutex);
	if (ret) {
		LOG_ERR("sys_mutex_unlock failed: %d", ret);
		return -ret;
	}

	return ret_lookup;
}

int easy_azure_connect(const char *device_id)
{
	int ret;
	int ret_mtx;
	az_result az_result;

	static char client_id[CLIENT_ID_MAX_LEN] = {0};
	size_t client_id_len = 0;
	static char user_name[USER_NAME_MAX_LEN] = {0};
	size_t user_name_len = 0;

	ret_mtx = k_mutex_lock(&api_lock, K_FOREVER);
	if (ret_mtx) {
		LOG_ERR("k_mutex_lock failed: %d", ret_mtx);
		return ret_mtx;
	}

	// ---

	az_result = az_iot_hub_client_init(&iot_hub_client, AZ_SPAN_FROM_STR(HOST),
					   az_span_create_from_str(device_id), NULL);
	if (az_result_failed(az_result)) {
		LOG_ERR("az_iot_hub_client_init failed: %d", az_result & 0xff);
		ret = -EINVAL;
		goto exit;
	}

	az_result = az_iot_hub_client_get_client_id(&iot_hub_client, client_id, sizeof(client_id),
						    &client_id_len);
	if (az_result_failed(az_result)) {
		LOG_ERR("az_iot_hub_client_get_client_id failed: %d", az_result & 0xff);
		ret = -EINVAL;
		goto exit;
	}

	mqtt_client.client_id.utf8 = client_id;
	mqtt_client.client_id.size = client_id_len;

	LOG_HEXDUMP_DBG(mqtt_client.client_id.utf8, mqtt_client.client_id.size, "client_id");

	az_result = az_iot_hub_client_get_user_name(&iot_hub_client, user_name, sizeof(user_name),
						    &user_name_len);
	if (az_result_failed(az_result)) {
		LOG_ERR("az_iot_hub_client_get_user_name failed: %d", az_result & 0xff);
		ret = -EINVAL;
		goto exit;
	}

	mqtt_client.user_name->utf8 = user_name;
	mqtt_client.user_name->size = user_name_len;

	LOG_HEXDUMP_DBG(mqtt_client.user_name->utf8, mqtt_client.user_name->size, "user_name");

	// ---

	ret = dns_lookup();
	if (ret) {
		LOG_ERR("DNS lookup failed: %d", ret);
		goto exit;
	}

	k_poll_signal_reset(&mqtt_connack_sig);

	if (IS_ENABLED(CONFIG_EASY_AZURE_DEVICE_TWIN)) {
		k_poll_signal_reset(&twin_received_sig);
	}

	if (IS_ENABLED(CONFIG_EASY_AZURE_DEVICE_TWIN) ||
	    IS_ENABLED(CONFIG_EASY_AZURE_C2D_MESSAGES) ||
	    IS_ENABLED(CONFIG_EASY_AZURE_DIRECT_METHODS)) {
		k_poll_signal_reset(&mqtt_suback_sig);
	}

	// Todo: Find a more pleasing implementation
	struct k_poll_event events[] = {
		K_POLL_EVENT_STATIC_INITIALIZER(K_POLL_TYPE_SIGNAL, K_POLL_MODE_NOTIFY_ONLY,
#ifdef CONFIG_EASY_AZURE_DEVICE_TWIN
						&twin_received_sig,
#elif CONFIG_EASY_AZURE_C2D_MESSAGES || CONFIG_EASY_AZURE_DIRECT_METHODS
						&mqtt_suback_sig,
#else
						&mqtt_connack_sig,
#endif
						0),
	};

	ret = mqtt_connect(&mqtt_client);
	if (ret) {
		LOG_ERR("mqtt_connect failed: %d", ret);
		goto exit;
	}

	ret = k_poll(events, ARRAY_SIZE(events), K_FOREVER);
	if (ret) {
		LOG_ERR("k_poll failed: %d", ret);
		goto exit;
	}

exit:
	ret_mtx = k_mutex_unlock(&api_lock);
	if (ret_mtx) {
		LOG_ERR("k_mutex_unlock failed: %d", ret_mtx);
		return ret_mtx;
	}

	return ret;
}

int easy_azure_disconnect(void)
{
	int ret;

	ret = k_mutex_lock(&api_lock, K_FOREVER);
	if (ret) {
		LOG_ERR("k_mutex_lock failed: %d", ret);
		return ret;
	}

	k_poll_signal_reset(&mqtt_disconnect_sig);

	struct k_poll_event events[] = {
		K_POLL_EVENT_STATIC_INITIALIZER(K_POLL_TYPE_SIGNAL, K_POLL_MODE_NOTIFY_ONLY,
						&mqtt_disconnect_sig, 0),
	};

	ret = mqtt_disconnect(&mqtt_client);
	if (ret) {
		LOG_ERR("mqtt_disconnect failed: %d", ret);
		goto exit;
	}

	ret = k_poll(events, ARRAY_SIZE(events), K_FOREVER);
	if (ret) {
		LOG_ERR("k_poll failed: %d", ret);
		goto exit;
	}

exit:
	ret = k_mutex_unlock(&api_lock);
	if (ret) {
		LOG_ERR("k_mutex_unlock failed: %d", ret);
		return ret;
	}

	return ret;
}

#ifdef CONFIG_EASY_AZURE_D2C_MESSAGES
int easy_azure_send_message(const uint8_t *message, size_t message_len)
{
	int ret;
	int ret_mtx;
	az_result az_result;

	ret_mtx = k_mutex_lock(&api_lock, K_FOREVER);
	if (ret_mtx) {
		LOG_ERR("k_mutex_lock failed: %d", ret_mtx);
		return ret_mtx;
	}

	char topic[MQTT_TOPIC_MAX_LEN] = {0};
	size_t topic_len = 0;

	az_result = az_iot_hub_client_telemetry_get_publish_topic(&iot_hub_client, NULL, topic,
								  sizeof(topic), &topic_len);
	if (az_result_failed(az_result)) {
		LOG_ERR("az_iot_hub_client_telemetry_get_publish_topic failed");
		ret = -EINVAL;
		goto exit;
	}

	struct mqtt_publish_param param = {
		.message.topic.qos = MQTT_QOS_1_AT_LEAST_ONCE,
		.message.topic.topic.utf8 = (uint8_t *)topic,
		.message.topic.topic.size = topic_len,
		.message.payload.data = (uint8_t *)message,
		.message.payload.len = message_len,
		.message_id = sys_rand32_get(),
	};

	k_poll_signal_reset(&mqtt_puback_sig);

	ret = mqtt_publish(&mqtt_client, &param);
	if (ret) {
		LOG_WRN("mqtt_publish failed: %d", ret);
		goto exit;
	}

	ret = k_poll(message_sent_events, ARRAY_SIZE(message_sent_events), K_FOREVER);
	if (ret) {
		LOG_ERR("k_poll failed: %d", ret);
		goto exit;
	}

exit:
	ret_mtx = k_mutex_unlock(&api_lock);
	if (ret_mtx) {
		LOG_ERR("k_mutex_unlock failed: %d", ret_mtx);
		return ret_mtx;
	}

	return ret;
}
#endif

static int subscribe_essentials()
{
	struct mqtt_topic topics[] = {
#ifdef CONFIG_EASY_AZURE_C2D_MESSAGES
		{
			.topic.utf8 = AZ_IOT_HUB_CLIENT_C2D_SUBSCRIBE_TOPIC,
			.topic.size = strlen(AZ_IOT_HUB_CLIENT_C2D_SUBSCRIBE_TOPIC),
			.qos = MQTT_QOS_1_AT_LEAST_ONCE,
		},
#endif
#ifdef CONFIG_EASY_AZURE_METHODS
		{
			.topic.utf8 = AZ_IOT_HUB_CLIENT_METHODS_SUBSCRIBE_TOPIC,
			.topic.size = strlen(AZ_IOT_HUB_CLIENT_METHODS_SUBSCRIBE_TOPIC),
			.qos = MQTT_QOS_1_AT_LEAST_ONCE,
		},
#endif
#ifdef CONFIG_EASY_AZURE_DEVICE_TWIN
		{
			.topic.utf8 = AZ_IOT_HUB_CLIENT_TWIN_RESPONSE_SUBSCRIBE_TOPIC,
			.topic.size = strlen(AZ_IOT_HUB_CLIENT_TWIN_RESPONSE_SUBSCRIBE_TOPIC),
			.qos = MQTT_QOS_1_AT_LEAST_ONCE,
		},
		{
			.topic.utf8 = AZ_IOT_HUB_CLIENT_TWIN_PATCH_SUBSCRIBE_TOPIC,
			.topic.size = strlen(AZ_IOT_HUB_CLIENT_TWIN_PATCH_SUBSCRIBE_TOPIC),
			.qos = MQTT_QOS_1_AT_LEAST_ONCE,
		},
#endif
	};

	struct mqtt_subscription_list topics_list = {
		.list = topics,
		.list_count = ARRAY_SIZE(topics),
		.message_id = sys_rand32_get(),
	};

	if (!topics_list.list_count) {
		return 0;
	}

	int ret = mqtt_subscribe(&mqtt_client, &topics_list);
	if (ret) {
		LOG_WRN("mqtt_subscribe failed: %d", ret);
	}

	return ret;
}

#ifdef CONFIG_EASY_AZURE_DEVICE_TWIN
static int request_device_twin(void)
{
	static char request_id[] = "0";

	char topic[MQTT_TOPIC_MAX_LEN] = {0};
	size_t topic_len = 0;

	az_result az_result = az_iot_hub_client_twin_document_get_publish_topic(
		&iot_hub_client, az_span_create_from_str(request_id), topic, sizeof(topic),
		&topic_len);
	if (az_result_failed(az_result)) {
		LOG_ERR("az_iot_hub_client_twin_document_get_publish_topic failed");
		return -1;
	}

	struct mqtt_publish_param param = {
		.message.topic.qos = MQTT_QOS_1_AT_LEAST_ONCE,
		.message.topic.topic.utf8 = (uint8_t *)topic,
		.message.topic.topic.size = topic_len,
		.message_id = sys_rand32_get(),
	};

	int ret = mqtt_publish(&mqtt_client, &param);
	if (ret) {
		LOG_WRN("mqtt_publish failed: %d", ret);
	}

	return ret;
}
#endif

static void handle_publish(struct mqtt_client *client, const struct mqtt_evt *event)
{
	int ret;

	const struct mqtt_publish_param *publish_param = &event->param.publish;
	const struct mqtt_topic *topic = &publish_param->message.topic;
	const struct mqtt_binstr *payload = &publish_param->message.payload;

	LOG_HEXDUMP_DBG(topic->topic.utf8, topic->topic.size, "topic");

	char buf[payload->len];
	ret = mqtt_readall_publish_payload(client, buf, payload->len);
	if (ret) {
		LOG_WRN("mqtt_readall_publish_payload failed: %d", ret);
	}

	LOG_HEXDUMP_DBG(buf, payload->len, "payload");

	if (topic->qos == MQTT_QOS_1_AT_LEAST_ONCE) {
		const struct mqtt_puback_param puback_param = {
			.message_id = publish_param->message_id,
		};

		ret = mqtt_publish_qos1_ack(client, &puback_param);
		if (ret) {
			LOG_WRN("mqtt_publish_qos1_ack failed: %d", ret);
		}
	}

	az_iot_hub_client_c2d_request c2d_request;
	if (az_result_succeeded(az_iot_hub_client_c2d_parse_received_topic(
		    &iot_hub_client,
		    az_span_create((uint8_t *)topic->topic.utf8, topic->topic.size),
		    &c2d_request))) {
		LOG_DBG("C2D message received");

		// Todo: Call handler

		return;
	}

	az_iot_hub_client_method_request method_request;
	if (az_result_succeeded(az_iot_hub_client_methods_parse_received_topic(
		    &iot_hub_client,
		    az_span_create((uint8_t *)topic->topic.utf8, topic->topic.size),
		    &method_request))) {
		LOG_DBG("Direct Method received");

		// Todo: Call handler

		return;
	}

	az_iot_hub_client_twin_response twin_response;
	if (az_result_succeeded(az_iot_hub_client_twin_parse_received_topic(
		    &iot_hub_client,
		    az_span_create((uint8_t *)topic->topic.utf8, topic->topic.size),
		    &twin_response))) {
		LOG_DBG("Device Twin received");

		ret = k_poll_signal_raise(&twin_received_sig, 0);
		if (ret) {
			LOG_WRN("k_poll_signal_raise failed: %d", ret);
		}

		// Todo: Call handler

		return;
	}
}

static void mqtt_event_cb(struct mqtt_client *client, const struct mqtt_evt *event)
{
	int ret;

	switch (event->type) {
	case MQTT_EVT_CONNACK:
		LOG_DBG("CONNACK: %d", event->result);

		ret = k_poll_signal_raise(&mqtt_connack_sig, 0);
		if (ret) {
			LOG_WRN("k_poll_signal_raise failed: %d", ret);
		}

		ret = subscribe_essentials();
		if (ret) {
			LOG_WRN("subscribe_essentials failed: %d", ret);
		}
		break;
	case MQTT_EVT_DISCONNECT:
		LOG_DBG("DISCONNECT: %d", event->result);

		ret = k_poll_signal_raise(&mqtt_disconnect_sig, 0);
		if (ret) {
			LOG_WRN("k_poll_signal_raise failed: %d", ret);
		}
		break;
	case MQTT_EVT_PUBLISH:
		LOG_DBG("PUBLISH: %d", event->result);
		handle_publish(client, event);
		break;
	case MQTT_EVT_PUBACK:
		LOG_DBG("PUBACK: %d", event->result);
		ret = k_poll_signal_raise(&mqtt_puback_sig, 0);

		if (ret) {
			LOG_WRN("k_poll_signal_raise failed: %d", ret);
		}
		break;
	case MQTT_EVT_PUBREC:
		LOG_DBG("PUBREC: %d", event->result);
		break;
	case MQTT_EVT_PUBREL:
		LOG_DBG("PUBREL: %d", event->result);
		break;
	case MQTT_EVT_PUBCOMP:
		LOG_DBG("PUBCOMP: %d", event->result);
		break;
	case MQTT_EVT_SUBACK:
		LOG_DBG("SUBACK: %d", event->result);

		ret = k_poll_signal_raise(&mqtt_suback_sig, 0);
		if (ret) {
			LOG_WRN("k_poll_signal_raise failed: %d", ret);
		}

#ifdef CONFIG_EASY_AZURE_DEVICE_TWIN
		ret = request_device_twin();
		if (ret) {
			LOG_WRN("request_device_twin failed: %d", ret);
		}
#endif

		break;
	case MQTT_EVT_UNSUBACK:
		LOG_DBG("UNSUBACK: %d", event->result);
		break;
	case MQTT_EVT_PINGRESP:
		LOG_DBG("PINGRESP: %d", event->result);
		break;
	}
}

static int easy_azure_init(const struct device *dev)
{
	static uint8_t rx_buf[MQTT_BUF_SIZE] = {0};
	static uint8_t tx_buf[MQTT_BUF_SIZE] = {0};
	static struct mqtt_utf8 mqtt_username = {0};
	static struct mqtt_utf8 mqtt_password = {0};
	static sec_tag_t sec_tags[] = {CONFIG_EASY_AZURE_SEC_TAG};

	mqtt_client_init(&mqtt_client);

	mqtt_client.protocol_version = MQTT_VERSION_3_1_1;
	mqtt_client.keepalive = AZ_IOT_DEFAULT_MQTT_CONNECT_KEEPALIVE_SECONDS;
	mqtt_client.evt_cb = mqtt_event_cb;

	/*
	 * Assign buffers
	 */
	mqtt_client.rx_buf = rx_buf;
	mqtt_client.rx_buf_size = sizeof(rx_buf);
	mqtt_client.tx_buf = tx_buf;
	mqtt_client.tx_buf_size = sizeof(tx_buf);
	mqtt_client.user_name = &mqtt_username;
	mqtt_client.password = &mqtt_password;

	/*
	 * Configure transport and security
	 */
	mqtt_client.transport.type = MQTT_TRANSPORT_SECURE;
	mqtt_client.transport.tls.config.peer_verify = TLS_PEER_VERIFY_REQUIRED;
	mqtt_client.transport.tls.config.cipher_count = 0;
	mqtt_client.transport.tls.config.cipher_list = NULL;
	mqtt_client.transport.tls.config.sec_tag_count = ARRAY_SIZE(sec_tags);
	mqtt_client.transport.tls.config.sec_tag_list = sec_tags;
	mqtt_client.transport.tls.config.hostname = HOST;

	return 0;
}

static void easy_azure_process()
{
	int ret;

	easy_azure_init(NULL);

	while (1) {
		ret = mqtt_input(&mqtt_client);
		switch (ret) {
		case 0:
		case -EACCES:
			break;
		default:
			LOG_WRN("mqtt_input failed: %d", ret);
			break;
		}

		ret = mqtt_live(&mqtt_client);
		switch (ret) {
		case 0:
		case -EAGAIN:
		case -ENOTCONN:
			break;
		default:
			LOG_WRN("mqtt_live failed: %d", ret);
			break;
		}

		k_sleep(K_MSEC(100));
	}
}

K_THREAD_DEFINE(easy_azure, KB(4), easy_azure_process, NULL, NULL, NULL, 0, 0, 0);
