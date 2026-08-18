/*
 * SPDX-FileCopyrightText: 2021-2023 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Unlicense OR CC0-1.0
 */

#ifndef H_ENC_ADV_DATA_PRPH_
#define H_ENC_ADV_DATA_PRPH_

#if CONFIG_EXAMPLE_ENC_ADV_DATA
#include <stdbool.h>
#include "nimble/ble.h"
#include "modlog/modlog.h"
#include "esp_peripheral.h"
#include "host/ble_ead.h"

#ifdef __cplusplus
extern "C" {
#endif

struct ble_hs_cfg;
struct ble_gatt_register_ctxt;

void gatt_svr_register_cb(struct ble_gatt_register_ctxt *ctxt, void *arg);
int gatt_svr_init(void);

#define LOG_TAG "YourProjectName"
#define pr_fmt(fmt) fmt
#define _FFL_TAG_ __FILE_NAME__, __func__, __LINE__
#define pr_err(fmt, ...)   do {  ESP_LOGE("", "[%s: %s: %d]	" pr_fmt(fmt), _FFL_TAG_, ##__VA_ARGS__); } while(0)
#define pr_warn(fmt, ...)  do {  ESP_LOGW("", "[%s: %s: %d]	" pr_fmt(fmt), _FFL_TAG_, ##__VA_ARGS__); } while(0)
#define pr_info(fmt, ...)  do { ESP_LOGI("", "[%s: %s: %d]	" pr_fmt(fmt), _FFL_TAG_, ##__VA_ARGS__); } while(0)

#ifdef __cplusplus
}
#endif
#endif
#endif
