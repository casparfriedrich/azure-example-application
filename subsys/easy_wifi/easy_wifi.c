#include "easy_wifi.h"

#include <zephyr/init.h>
#include <zephyr/logging/log.h>
#include <zephyr/net/net_event.h>
#include <zephyr/net/net_if.h>
#include <zephyr/net/net_mgmt.h>
#include <zephyr/net/wifi_mgmt.h>
#include <zephyr/zephyr.h>

LOG_MODULE_REGISTER(easy_wifi, LOG_LEVEL_DBG);

#define NET_EVENT_IPV4_SET (NET_EVENT_IPV4_ADDR_ADD)
#define NET_EVENT_L4_SET   (NET_EVENT_DNS_SERVER_ADD)
#define WIFI_EVENT_SET	   (NET_EVENT_WIFI_CONNECT_RESULT | NET_EVENT_WIFI_DISCONNECT_RESULT)

static struct k_poll_signal sig_connected = K_POLL_SIGNAL_INITIALIZER(sig_connected);
static struct k_poll_signal sig_disconnected = K_POLL_SIGNAL_INITIALIZER(sig_disconnected);

static void event_handler(struct net_mgmt_event_callback *cb, uint32_t mgmt_event,
			  struct net_if *iface)
{
	int ret;

	switch (mgmt_event) {
	case NET_EVENT_IPV4_ADDR_ADD:
		LOG_DBG("NET_EVENT_IPV4_ADDR_ADD");
		break;
	case NET_EVENT_DNS_SERVER_ADD:
		LOG_DBG("NET_EVENT_DNS_SERVER_ADD");
		ret = k_poll_signal_raise(&sig_connected, 0);
		if (ret) {
			LOG_ERR("k_poll_signal_raise failed: %d", ret);
			return;
		}
		break;
	case NET_EVENT_WIFI_CONNECT_RESULT:
		LOG_DBG("NET_EVENT_WIFI_CONNECT_RESULT");
		break;
	case NET_EVENT_WIFI_DISCONNECT_RESULT:
		LOG_DBG("NET_EVENT_WIFI_DISCONNECT_RESULT");
		ret = k_poll_signal_raise(&sig_disconnected, 0);
		if (ret) {
			LOG_ERR("k_poll_signal_raise failed: %d", ret);
			return;
		}
		break;
	default:
		break;
	}
}

int easy_wifi_connect(const char *ssid, const char *psk, k_timeout_t timeout)
{
	int ret;

	while (!net_if_is_up(net_if_get_default())) {
		k_sleep(K_MSEC(100));
	}

	struct wifi_connect_req_params params = {
		.ssid = (uint8_t *)ssid, .ssid_length = strlen(ssid), .channel = WIFI_CHANNEL_ANY};

	if (psk) {
		params.psk = (uint8_t *)psk;
		params.psk_length = strlen(psk);
		params.security = WIFI_SECURITY_TYPE_PSK;
	}

	static struct k_poll_event events[] = {K_POLL_EVENT_STATIC_INITIALIZER(
		K_POLL_TYPE_SIGNAL, K_POLL_MODE_NOTIFY_ONLY, &sig_connected, 0)};

	k_poll_signal_reset(&sig_connected);

	ret = net_mgmt(NET_REQUEST_WIFI_CONNECT, net_if_get_default(), &params, sizeof(params));
	if (ret) {
		LOG_WRN("NET_REQUEST_WIFI_CONNECT: %d", ret);
		return ret;
	}

	ret = k_poll(events, ARRAY_SIZE(events), timeout);
	if (ret) {
		LOG_ERR("k_poll failed: %d", ret);
		return ret;
	}

	return 0;
}

int easy_wifi_disconnect(k_timeout_t timeout)
{
	int ret;

	static struct k_poll_event events[] = {K_POLL_EVENT_STATIC_INITIALIZER(
		K_POLL_TYPE_SIGNAL, K_POLL_MODE_NOTIFY_ONLY, &sig_disconnected, 0)};

	k_poll_signal_reset(&sig_disconnected);

	ret = net_mgmt(NET_REQUEST_WIFI_DISCONNECT, net_if_get_default(), NULL, 0);
	if (ret) {
		LOG_ERR("NET_REQUEST_WIFI_DISCONNECT failed: %d", ret);
		return ret;
	}

	ret = k_poll(events, ARRAY_SIZE(events), timeout);
	if (ret) {
		LOG_ERR("k_poll failed: %d", ret);
		return ret;
	}

	return 0;
}

static int easy_wifi_init(const struct device *dev)
{
	static struct net_mgmt_event_callback wifi_event_cb;
	net_mgmt_init_event_callback(&wifi_event_cb, event_handler, WIFI_EVENT_SET);
	net_mgmt_add_event_callback(&wifi_event_cb);

	static struct net_mgmt_event_callback net_event_ipv4_cb;
	net_mgmt_init_event_callback(&net_event_ipv4_cb, event_handler, NET_EVENT_IPV4_SET);
	net_mgmt_add_event_callback(&net_event_ipv4_cb);

	static struct net_mgmt_event_callback net_event_l4_cb;
	net_mgmt_init_event_callback(&net_event_l4_cb, event_handler, NET_EVENT_L4_SET);
	net_mgmt_add_event_callback(&net_event_l4_cb);

	return 0;
}

SYS_INIT(easy_wifi_init, APPLICATION, CONFIG_APPLICATION_INIT_PRIORITY);
