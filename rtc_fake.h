

// SPDX-License-Identifier: BSD-3-Clause
// From https://github.com/raspberrypi/pico-sdk/blob/6a7db34ff63345a7badec79ebea3aaef1712f374/src/common/pico_base/include/pico/types.h
typedef struct {
    int16_t year;    ///< 0..4095
    int8_t month;    ///< 1..12, 1 is January
    int8_t day;      ///< 1..28,29,30,31 depending on month
    int8_t dotw;     ///< 0..6, 0 is Sunday
    int8_t hour;     ///< 0..23
    int8_t min;      ///< 0..59
    int8_t sec;      ///< 0..59
} datetime_t;

// SPDX-License-Identifier: BSD-3-Clause
// From https://github.com/raspberrypi/pico-sdk/blob/6a7db34ff63345a7badec79ebea3aaef1712f374/src/rp2_common/hardware_rtc/include/hardware/rtc.h
void rtc_init(void);
bool rtc_running(void);
uint64_t time_us_64(void);
bool rtc_set_datetime(datetime_t *t);
bool rtc_get_datetime(datetime_t *t);


// SPDX-License-Identifier: BSD-3-Clause
// From https://github.com/raspberrypi/pico-sdk/blob/6a7db34ff63345a7badec79ebea3aaef1712f374/src/rp2_common/pico_unique_id/include/pico/unique_id.h
#define PICO_UNIQUE_BOARD_ID_SIZE_BYTES 8

typedef struct {
    uint8_t id[PICO_UNIQUE_BOARD_ID_SIZE_BYTES];
} pico_unique_board_id_t;

void pico_get_unique_board_id(pico_unique_board_id_t *id_out);