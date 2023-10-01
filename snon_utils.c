// ---------------------------------------------------------------------------------
// SNON Utilities
// ---------------------------------------------------------------------------------
// Provides standard routines to register and manipulate SNON entities
// See https://www.snon.org/ for more details
// ---------------------------------------------------------------------------------
// SPDX-FileCopyrightText: Copyright 2023 David Slik (VE7FIM)
// SPDX-FileAttributionText: https://github.com/dslik/snon-utils/
// SPDX-License-Identifier: CERN-OHL-S-2.0
// ---------------------------------------------------------------------------------

// System Headers
#include <stdio.h>
#include <time.h>
#include <stdlib.h>

// Pico Headers
#if !defined(__x86_64__)
#include "pico/stdlib.h"
#include "pico/unique_id.h"
#include "hardware/rtc.h"
#endif

// Local mac target
#if defined(__x86_64__)
#include <stdbool.h>
#include "rtc_fake.h"
#endif

// Local Headers
#include "snon_utils.h"
#include "sha1.h"
#include "cJSON.h"

// Local Constants
#define SNON_URN            "urn:uuid:C3A4DD12-EFD4-537A-885C-50EC74A2CB12"

// Local Prototypes
bool snon_resolve(char* entity_ref, char* eid);

bool rtc_now_to_counter(char* buffer);
bool rtc_now_to_iso8601(char* buffer);
bool rtc_counter_to_iso8601(char* buffer, uint64_t counter);
void device_get_id(uint64_t* id);
char nibble_to_hexchar(uint8_t nibble);
bool string_only_numbers(char* the_string);
void string_char_sub(char* the_string, char orig, char sub);
bool string_strip_right(char* string, char character);


// Local Globals
cJSON*   snon_root = NULL;
cJSON*   snon_list = NULL;

uint64_t rtc_set_count = 0;
uint64_t rtc_set_epoch = 0;


// =================================================================================

void snon_initialize(char* entity_name)
{
    char    eid[SNON_URN_LENGTH];
    char    current_time[28];
    cJSON*  entity = NULL;
    cJSON*  name = NULL;
    cJSON*  array = NULL;
    cJSON*  eid_string = NULL;

    rtc_init();

    snon_root = cJSON_CreateObject();
    snon_list = cJSON_CreateArray();

    // Create the device entity
    snon_name_to_eid("Device", eid);
    cJSON_AddItemToObject(snon_root, eid, entity = cJSON_CreateObject());
    cJSON_AddItemToObjectCS(entity, "eC", cJSON_CreateStringReference("device"));
    cJSON_AddItemToObjectCS(entity, "eID", eid_string = cJSON_CreateString(eid));
    cJSON_AddItemToObjectCS(entity, "eN", name = cJSON_CreateObject());
    cJSON_AddItemToObjectCS(name, "*", cJSON_CreateString(entity_name));

    // Add the entity to the master entity list
    cJSON_AddItemReferenceToArray(snon_list, eid_string);

    // Create the entity list entity
    snon_name_to_eid("Entities", eid);
    cJSON_AddItemToObject(snon_root, eid, entity = cJSON_CreateObject());
    cJSON_AddItemToObjectCS(entity, "eC", cJSON_CreateStringReference("value"));
    cJSON_AddItemToObjectCS(entity, "eID", eid_string = cJSON_CreateString(eid));
    cJSON_AddItemToObjectCS(entity, "eN", name = cJSON_CreateObject());
    cJSON_AddItemToObjectCS(name, "*", cJSON_CreateStringReference("Entities"));
    cJSON_AddItemToObjectCS(entity, "v", snon_list);
    cJSON_AddItemToObjectCS(entity, "vT", array = cJSON_CreateArray());
    rtc_now_to_counter(current_time);
    cJSON_AddItemToArray(array, cJSON_CreateString(current_time));

    // Add the entity to the master entity list
    cJSON_AddItemReferenceToArray(snon_list, eid_string);
}

bool snon_register(char* entity_name, char* entity_class, char* initial_values)
{
    char    eid[SNON_URN_LENGTH];
    char    current_time[28];
    cJSON*  entity = NULL;
    cJSON*  name = NULL;
    cJSON*  valueString = NULL;
    cJSON*  array = NULL;
    cJSON*  eid_string = NULL;
    bool    register_result = false;
    extern int __bss_start__;

    snon_name_to_eid(entity_name, eid);

    if(initial_values != NULL)
    {
        // If additional data is passed, parse it
        entity = cJSON_Parse(initial_values);
    }
    else
    {
        // Otherwise, create an empty object for the entity
        entity = cJSON_CreateObject();
    }

    if(entity != NULL)
    {
        cJSON_AddItemToObject(snon_root, eid, entity);
        cJSON_AddItemToObjectCS(entity, "eID", eid_string = cJSON_CreateString(eid));
        cJSON_AddItemToObjectCS(entity, "eC", cJSON_CreateStringReference(entity_class));
        cJSON_AddItemToObjectCS(entity, "eN", name = cJSON_CreateObject());
        
        if(entity_name < (char*) &__bss_start__)
        {
            valueString = cJSON_CreateStringReference(entity_name);
        }
        else
        {
            valueString = cJSON_CreateString(entity_name);
        }
        
        cJSON_AddItemToObjectCS(name, "*", valueString);

        if(strcmp(entity_class, SNON_CLASS_VALUE) == 0)
        {
            rtc_now_to_counter(current_time);

            cJSON_AddItemToObjectCS(entity, "vT", array = cJSON_CreateArray());
            cJSON_AddItemToArray(array, cJSON_CreateString(current_time));
        }

        if(strcmp(entity_name, "Device Time") == 0 ||
           strcmp(entity_name, "Device Uptime") == 0)
        {
            cJSON_AddItemToObjectCS(entity, "v", array = cJSON_CreateArray());
            cJSON_AddItemToArray(array, cJSON_CreateString(current_time));
        }

        cJSON_AddItemReferenceToArray(snon_list, eid_string);
        register_result = true;
    }

    return(register_result);
}

bool snon_register_81346(char* entity_name, char* entity_class, char* initial_value)
{
    cJSON*  parent_name = cJSON_CreateString(entity_name);
    char*   parent_string = NULL;
    bool    register_result = false;
    bool    parent_found = false;

    register_result = snon_register(entity_name, entity_class, NULL);

    if(register_result == true)
    {
        if(initial_value != NULL)
        {
            snon_set_value(entity_name, initial_value);            
        }

        parent_string = cJSON_GetStringValue(parent_name);
        parent_found = string_strip_right(parent_string, '=');

        if(parent_found == true)
        {
            snon_add_relationship(entity_name, SNON_REL_CHILD_OF, parent_string);
        }
    }

    cJSON_Delete(parent_name);

    return(register_result);
}

bool snon_resolve(char* entity_ref, char* eid)
{
    // Check if the entity reference is a UUID
    if(strncmp(entity_ref, "urn:uuid:", 9) == 0)
    {
        // Entity reference is a UUID
        if(strlen(entity_ref) != SNON_URN_LENGTH - 1)
        {
            return(false);
        }
        else
        {
            strncpy(eid, entity_ref, SNON_URN_LENGTH);
        }
    }
    else
    {
        // Entity reference is a name, get the UUID
        snon_name_to_eid(entity_ref, eid);
    }

    return(true);
}


bool snon_add_relationship(char* entity_ref, char* rel_type, char* rel_entity_name)
{
    char        eid[SNON_URN_LENGTH];
    cJSON*      entity = NULL;
    cJSON*      rel = NULL;
    cJSON*      array = NULL;
    bool        add_result = false;

    if(snon_resolve(entity_ref, eid) == true)
    {
        entity = cJSON_GetObjectItemCaseSensitive(snon_root, eid);
        if(entity != NULL)
        {
            rel = cJSON_GetObjectItemCaseSensitive(entity, "eR");

            if(rel == NULL)
            {
                cJSON_AddItemToObjectCS(entity, "eR", rel = cJSON_CreateObject());
            }

            array = cJSON_GetObjectItemCaseSensitive(rel, rel_type);

            if(array == NULL)
            {
                cJSON_AddItemToObjectCS(rel, rel_type, array = cJSON_CreateArray());
            }

            snon_name_to_eid(rel_entity_name, eid);
            cJSON_AddItemToArray(array, cJSON_CreateString(eid));

            add_result = true;
        }
    }

    return(add_result);
}


bool snon_set_values(char* entity_ref, char* updated_values)
{
    char        eid[SNON_URN_LENGTH];
    char        eid2[SNON_URN_LENGTH];
    char        current_time[28];
    cJSON*      entity = NULL;
    cJSON*      new_value = NULL;
    cJSON*      new_time_value = NULL;
    char*       new_time_value_string = NULL;
    cJSON*      value_array = NULL;
    cJSON*      value_time_array = NULL;
    cJSON*      array = NULL;
    bool        is_time_entity = false;
    bool        set_result = false;

    if(snon_resolve(entity_ref, eid) == true)
    {
        // Check if it is the time entity
        snon_name_to_eid("Device Time", eid2);
        if(strcmp(eid, eid2) == 0)
        {
            is_time_entity = true;
        }

        // Parse the value array
        new_value = cJSON_Parse(updated_values);

        if(new_value != NULL)
        {
            // Find the entity by UUID
            entity = cJSON_GetObjectItemCaseSensitive(snon_root, eid);
            if(entity != NULL)
            {
                rtc_now_to_counter(current_time);
                
                value_array = cJSON_GetObjectItemCaseSensitive(entity, "v");
                if(value_array != NULL)
                {
                    cJSON_DeleteItemFromObjectCaseSensitive(entity, "v");
                }

                // Special case for updating the time
                if(is_time_entity)
                {
                    new_time_value = cJSON_GetArrayItem(new_value, 0);
                    if(new_time_value != NULL)
                    {
                        new_time_value_string = cJSON_GetStringValue(new_time_value);
                        rtc_set_time(new_time_value_string);
                    }

                    cJSON_AddItemToObjectCS(entity, "v", array = cJSON_CreateArray());
                    cJSON_AddItemToArray(array, cJSON_CreateString(current_time));
                }
                else
                {
                    cJSON_AddItemToObjectCS(entity, "v", new_value);
                }

                value_time_array = cJSON_GetObjectItemCaseSensitive(entity, "vT");
                if(value_time_array != NULL)
                {
                    cJSON_DeleteItemFromObjectCaseSensitive(entity, "vT");
                }

                cJSON_AddItemToObjectCS(entity, "vT", array = cJSON_CreateArray());
                cJSON_AddItemToArray(array, cJSON_CreateString(current_time));

                set_result = true;
            }
            else
            {
                cJSON_Delete(new_value);
            }
        }
        else
        {
            printf("\nError: Invalid value %s", updated_values);
        }
    }

    return(set_result);
}

bool snon_set_value(char* entity_ref, char* updated_value)
{
    char        eid[SNON_URN_LENGTH];
    char        eid2[SNON_URN_LENGTH];
    char        current_time[28];
    cJSON*      entity = NULL;
    cJSON*      new_time_value = NULL;
    char*       new_time_value_string = NULL;
    cJSON*      value_array = NULL;
    cJSON*      value_time_array = NULL;
    cJSON*      array = NULL;
    cJSON*      updated_value_data = NULL;
    bool        is_time_entity = false;
    bool        set_result = false;
    extern int  __bss_start__;

    if(snon_resolve(entity_ref, eid) == true)
    {
        // Check if it is the time entity
        snon_name_to_eid("Device Time", eid2);
        if(strcmp(eid, eid2) == 0)
        {
            is_time_entity = true;
        }

        // Find the entity by UUID
        entity = cJSON_GetObjectItemCaseSensitive(snon_root, eid);
        if(entity != NULL)
        {
            rtc_now_to_counter(current_time);
            
            value_array = cJSON_GetObjectItemCaseSensitive(entity, "v");
            if(value_array != NULL)
            {
                cJSON_Delete(cJSON_DetachItemFromObject(entity, "v"));
            }

            // Special case for updating the time
            if(is_time_entity)
            {
                rtc_set_time(updated_value);
                cJSON_AddItemToObjectCS(entity, "v", array = cJSON_CreateArray());
                cJSON_AddItemToArray(array, cJSON_CreateString(current_time));
            }
            else
            {
                cJSON_AddItemToObjectCS(entity, "v", array = cJSON_CreateArray());

                if(updated_value < (char*) &__bss_start__)
                {
                    updated_value_data = cJSON_CreateStringReference(updated_value);
                }
                else
                {
                    updated_value_data = cJSON_CreateString(updated_value);
                }
                
                cJSON_AddItemToArray(array, updated_value_data);
            }

            value_time_array = cJSON_GetObjectItemCaseSensitive(entity, "vT");
            if(value_time_array != NULL)
            {
                cJSON_Delete(cJSON_DetachItemFromObject(entity, "vT"));
            }

            cJSON_AddItemToObjectCS(entity, "vT", array = cJSON_CreateArray());
            cJSON_AddItemToArray(array, cJSON_CreateString(current_time));

            set_result = true;
        }
    }

    return(set_result);
}

char* snon_get_json(char* entity_ref)
{
    char        eid[SNON_URN_LENGTH];
    char        eid2[SNON_URN_LENGTH];
    char        new_time[28];
    char*       entity_json = NULL;
    cJSON*      entity = NULL;
    cJSON*      time_array = NULL;
    cJSON*      entity_time = NULL;
    cJSON*      value_array = NULL;
    char*       entity_time_string = NULL;
    uint64_t    entity_time_value = 0;
    bool        is_time_entity = false;
    bool        is_uptime_entity = false;

    if(snon_resolve(entity_ref, eid) == true)
    {
        // Check if it is the time entity
        snon_name_to_eid("Device Time", eid2);
        if(strcmp(eid, eid2) == 0)
        {
            is_time_entity = true;
        }

        snon_name_to_eid("Device Uptime", eid2);
        if(strcmp(eid, eid2) == 0)
        {
            is_uptime_entity = true;
        }

        // Find the entity by UUID
        entity = cJSON_GetObjectItemCaseSensitive(snon_root, eid);
        if(entity != NULL)
        {
            time_array = cJSON_GetObjectItemCaseSensitive(entity, "vT");

            if(time_array != NULL)
            {
                if(is_time_entity || is_uptime_entity)
                {
                    // Special handling for the device time entity
                    entity_time_value = time_us_64();
                    if(rtc_counter_to_iso8601(new_time, entity_time_value) == false)
                    {
                        rtc_now_to_counter(new_time);
                    }

                    cJSON_ReplaceItemInArray(time_array, 0, cJSON_CreateString(new_time));

                    value_array = cJSON_GetObjectItemCaseSensitive(entity, "v");
                    if(value_array != NULL)
                    {
                        if(is_uptime_entity)
                        {
                            rtc_now_to_counter(new_time);
                        }

                        cJSON_ReplaceItemInArray(value_array, 0, cJSON_CreateString(new_time));
                    }
                }
                else
                {
                    entity_time = cJSON_GetArrayItem(time_array, 0);
                    entity_time_string = cJSON_GetStringValue(entity_time);
                    
                    // Only replace if it is a raw timestamp
                    if(string_only_numbers(entity_time_string))
                    {
                        sscanf(entity_time_string, "%llu", &entity_time_value);
                        if(rtc_counter_to_iso8601(new_time, entity_time_value) == true)
                        {
                            cJSON_ReplaceItemInArray(time_array, 0, cJSON_CreateString(new_time));
                        }
                    }
                }
            }
        }

        if(entity != NULL)
        {
            entity_json = cJSON_PrintUnformatted(entity);
        }
    }

    return(entity_json);
}

char* snon_get_values(char* entity_ref)
{
    char        eid[SNON_URN_LENGTH];
    char*       entity_json = NULL;
    cJSON*      entity = NULL;
    cJSON*      value_array = NULL;

    if(snon_resolve(entity_ref, eid) == true)
    {
        // Find the entity by UUID
        entity = cJSON_GetObjectItemCaseSensitive(snon_root, eid);
        if(entity != NULL)
        {
            value_array = cJSON_GetObjectItemCaseSensitive(entity, "v");

            if(value_array != NULL)
            {
                entity_json = cJSON_PrintUnformatted(value_array);
            }
        }
    }

    return(entity_json);
}

char* snon_get_value(char* entity_ref)
{
    char        eid[SNON_URN_LENGTH];
    char*       entity_value = NULL;
    cJSON*      entity = NULL;
    cJSON*      value_array = NULL;
    cJSON*      value_array_item = NULL;

    if(snon_resolve(entity_ref, eid) == true)
    {
        // Find the entity by UUID
        entity = cJSON_GetObjectItemCaseSensitive(snon_root, eid);
        if(entity != NULL)
        {
            value_array = cJSON_GetObjectItemCaseSensitive(entity, "v");
            if(value_array != NULL)
            {
                value_array_item = cJSON_GetArrayItem(value_array, 0);
                if(value_array_item != NULL)
                {
                    entity_value = cJSON_GetStringValue(value_array_item);
                }
            }
        }
    }

    return(entity_value);
}

double snon_get_value_as_double(char* entity_ref)
{
    char*   entity_value = snon_get_value(entity_ref);
    double  entity_double = 0;

    if(entity_value != NULL)
    {
        entity_double = atof(entity_value);
    }

    return(entity_double);
}


char* snon_get_name(char* entity_ref)
{
    char        eid[SNON_URN_LENGTH];
    char*       entity_name = NULL;
    cJSON*      entity = NULL;
    cJSON*      value_name_container = NULL;
    cJSON*      value_name_object = NULL;

    if(snon_resolve(entity_ref, eid) == true)
    {
        // Find the entity by UUID
        entity = cJSON_GetObjectItemCaseSensitive(snon_root, eid);
        if(entity != NULL)
        {
            value_name_container = cJSON_GetObjectItemCaseSensitive(entity, "eN");

            if(value_name_container != NULL)
            {
                value_name_object = cJSON_GetObjectItemCaseSensitive(value_name_container, "*");

                if(value_name_object != NULL)
                {
                    entity_name = cJSON_GetStringValue(value_name_object);
                }
            }
        }
    }

    return(entity_name);
}

void snon_name_to_eid(const char* entity_name, char* eid_buffer)
{
    uint64_t    device_id = 0;
    SHA1_CTX    sha1_context;
    uint8_t     sha1_result[20];
    uint8_t     counter = 0;
    uint8_t     offset = 9;

    device_get_id(&device_id);

    SHA1Init(&sha1_context);
    SHA1Update(&sha1_context, SNON_URN, strlen(SNON_URN));
    SHA1Update(&sha1_context, &device_id, 8);
    SHA1Update(&sha1_context, entity_name, strlen(entity_name));
    SHA1Final(&sha1_result, &sha1_context);

    eid_buffer[0] = 'u';
    eid_buffer[1] = 'r';
    eid_buffer[2] = 'n';
    eid_buffer[3] = ':';
    eid_buffer[4] = 'u';
    eid_buffer[5] = 'u';
    eid_buffer[6] = 'i';
    eid_buffer[7] = 'd';
    eid_buffer[8] = ':';
    eid_buffer[SNON_URN_LENGTH - 1] = 0;

    while(counter < 16)
    {
        if(counter == 4 || counter == 6 || counter == 8 || counter == 10)
        {
            eid_buffer[(counter * 2) + offset] = '-';
            offset = offset + 1;
        }

        eid_buffer[(counter * 2) + offset] = nibble_to_hexchar(sha1_result[counter] >> 4);
        eid_buffer[(counter * 2) + 1 + offset] = nibble_to_hexchar(sha1_result[counter] & 0x0F);

        if(counter == 6)
        {
            eid_buffer[(counter * 2) + offset] = '5';
        }

        if(counter == 8)
        {
            eid_buffer[(counter * 2) + offset] = nibble_to_hexchar(((sha1_result[counter] >> 4) & 0b1011) | 0b1000);
        }

        counter = counter + 1;
    }
}

char* snon_get_dump(void)
{
    char*       entity_json = NULL;

    entity_json = cJSON_Print(snon_root);

    return(entity_json);
}

bool json_has_eid(const char* entity_json, char* uuid_buffer)
{
    cJSON*  entity = NULL;
    cJSON*  eID = NULL;
    char*   eID_string = NULL;
    bool    has_eID = false;

    entity = cJSON_Parse(entity_json);

    if(entity != NULL)
    {
        eID = cJSON_GetObjectItemCaseSensitive(entity, "eID");

        if(eID != NULL)
        {
            eID_string = cJSON_GetStringValue(eID);
            strcpy(uuid_buffer, eID_string);

            has_eID = true;
        }

        cJSON_Delete(entity);
    }

    return(has_eID);
}

bool json_has_value(const char* entity_json, char* value_buffer)
{
    cJSON*  entity = NULL;
    cJSON*  value_array = NULL;
    char*   value_array_string = NULL;
    bool    has_value = false;

    entity = cJSON_Parse(entity_json);

    if(entity != NULL)
    {
        value_array = cJSON_GetObjectItemCaseSensitive(entity, "v");

        if(value_array != NULL)
        {
            value_array_string = cJSON_PrintUnformatted(value_array);
            strcpy(value_buffer, value_array_string);
            cJSON_free(value_array_string);

            has_value = true;
        }

        cJSON_Delete(entity);
    }

    return(has_value);
}

// =================================================================================

bool rtc_now_to_counter(char* buffer)
{
    snprintf(buffer, 28, "%llu", time_us_64());

    return(true);
}

bool rtc_now_to_iso8601(char* buffer)
{
    bool        get_time_valid = false;
    datetime_t  t;

    // Length of ISO8601 string used here is 28 characters:
    // "YYYY-MM-DDTHH:MM:SS.123456Z"
    //  123456789012345678901234567

    get_time_valid = rtc_get_datetime(&t);

    if(get_time_valid == true)
    {
        snprintf(buffer, 28, "%04d-%02d-%02dT%02d:%02d:%02d.%06lluZ", t.year, t.month, t.day, t.hour, t.min, t.sec, (time_us_64() % 1000000));
    }
    
    return(get_time_valid);
}

bool rtc_set_time(char* time_iso8601)
{
    unsigned int    year = 0;
    unsigned int    month = 0;
    unsigned int    day = 0;
    unsigned int    hours = 0;
    unsigned int    minutes = 0;
    unsigned int    seconds = 0;
    bool            set_valid = true;
    uint64_t        before_count = 0;
    uint64_t        after_count = 0;
    datetime_t      time_pico;
    struct tm       time_c;

    sscanf(time_iso8601, "%4u-%2u-%2uT%2u:%2u:%2uZ", &year, &month, &day, &hours, &minutes, &seconds);
    if(year < 2022 || year > 2055)
    {
        set_valid = false;
    }
    else if(month < 1 || month > 12)
    {
        set_valid = false;
    }
    else if(day < 1 || day > 31)
    {
        set_valid = false;
    }
    else if(hours < 0 || hours > 23)
    {
        set_valid = false;
    }
    else if(minutes < 0 || minutes > 59)
    {
        set_valid = false;
    }
    else if(seconds < 0 || seconds > 59)
    {
        set_valid = false;
    }
    
    if(set_valid == true)
    {
        time_pico.year = time_c.tm_year = year;
        time_pico.month = time_c.tm_mon = month;
        time_pico.day = time_c.tm_mday = day;
        time_pico.hour = time_c.tm_hour = hours;
        time_pico.min = time_c.tm_min = minutes;
        time_pico.sec = time_c.tm_sec = seconds;
        time_pico.dotw = 0;
        time_c.tm_isdst = -1;

        before_count = time_us_64();
        set_valid = rtc_set_datetime(&time_pico);
        after_count = time_us_64();

        rtc_set_count = after_count - ((after_count - before_count) / 2);
        rtc_set_epoch = (uint64_t) mktime(&time_c);

        printf("\nsc = %llu, offset = %llu", rtc_set_count, rtc_set_epoch);


    }

    return(set_valid);
}

bool rtc_counter_to_iso8601(char* buffer, uint64_t counter)
{
    bool        get_time_valid = false;
    struct tm   time;
    int64_t     offset_counter = 0;
    uint64_t    epoch_counter = 0;
    time_t      epoch_counter_secs = 0;

    // Length of ISO8601 string used here is 28 characters:
    // "YYYY-MM-DDTHH:MM:SS.123456Z"
    //  123456789012345678901234567

    if(rtc_running())
    {
        offset_counter = counter - rtc_set_count;
        epoch_counter = (rtc_set_epoch * 1000000) + offset_counter;
        epoch_counter_secs = epoch_counter / 1000000;

        gmtime_r(&epoch_counter_secs, &time);

        snprintf(buffer, 28, "%04d-%02d-%02dT%02d:%02d:%02d.%06lluZ",
                 time.tm_year, time.tm_mon, time.tm_mday,
                 time.tm_hour, time.tm_min, time.tm_sec,
                 (epoch_counter % 1000000));

        get_time_valid = true;
    }
    
    return(get_time_valid);
}

void device_get_id(uint64_t* id)
{
    pico_unique_board_id_t board_id;
    pico_get_unique_board_id(&board_id);
    *id = *((uint64_t*)(board_id.id));
}

char nibble_to_hexchar(uint8_t nibble)
{
    char hex_value = '_';

    if(nibble <= 9)
    {
        hex_value = '0' + nibble;
    }
    else if(nibble <= 15)
    {
        hex_value = 'A' + nibble - 10;
    }

    return(hex_value);
}

bool string_only_numbers(char* the_string)
{
    bool        only_numbers = true;
    uint16_t    string_counter = 0;

    while(the_string[string_counter] != 0 && only_numbers == true)
    {
        if(the_string[string_counter] < '0' || the_string[string_counter] > '9')
        {
            only_numbers = false;
        }

        string_counter = string_counter + 1;
    }

    return(only_numbers);
}

void string_char_sub(char* the_string, char orig, char sub)
{
    uint16_t    string_counter = 0;

    while(the_string[string_counter] != 0)
    {
        if(the_string[string_counter] == orig)
        {
            the_string[string_counter] = sub;
        }

        string_counter = string_counter + 1;
    }
}

bool string_strip_right(char* string, char character)
{
    uint16_t    string_loc = strlen(string);
    bool        char_found = false;

    while(string_loc != 0)
    {
        if(string[string_loc - 1] == character)
        {
            char_found = true;
            string[string_loc - 1] = 0;
            string_loc = 1;
        }

        string_loc = string_loc - 1;
    }

    return(char_found);
}


