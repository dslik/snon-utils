// ---------------------------------------------------------------------------------
// SNON Utilities - Header
// ---------------------------------------------------------------------------------
// Provides standard routines to register and manipulate SNON entities
// See https://www.snon.org/ for more details
// ---------------------------------------------------------------------------------
// SPDX-FileCopyrightText: Copyright 2023 David Slik (VE7FIM)
// SPDX-FileAttributionText: https://github.com/dslik/snon-utils/
// SPDX-License-Identifier: CERN-OHL-S-2.0
// ---------------------------------------------------------------------------------

// Utility routines
void snon_initialize(char* device_name);

bool snon_register(char* entity_name, char* entity_class, char* initial_values);
bool snon_register_81346(char* entity_name, char* entity_class, char* initial_value);
bool snon_add_relationship(char* entity_ref, char* rel_type, char* rel_entity_name);
bool snon_set_values(char* entity_ref, char* updated_values);
bool snon_set_value(char* entity_ref, char* updated_value);
char* snon_get_json(char* entity_ref);
char* snon_get_name(char* entity_ref);
char* snon_get_values(char* entity_ref);
char* snon_get_value(char* entity_ref);
double snon_get_value_as_double(char* entity_ref);
void snon_name_to_eid(const char* entity_name, char* eid_buffer);

char* snon_get_dump(void);

bool json_has_eid(const char* entity_json, char* uuid_buffer);
bool json_has_value(const char* entity_json, char* value_buffer);

bool rtc_set_time(char* time_iso8601);
bool rtc_counter_to_iso8601(char* buffer, uint64_t counter);

// Defines
#define SNON_URN_LENGTH     	46

// SNON Classes
#define SNON_CLASS_DEVICE		"device"
#define SNON_CLASS_LOCATION		"location"
#define SNON_CLASS_SENSOR		"sensor"
#define SNON_CLASS_MEASURAND	"measurand"
#define SNON_CLASS_SERIES		"series"
#define SNON_CLASS_VALUE		"value"

// SNON Relationships
#define	SNON_REL_CHILD_OF		"child_of"
#define	SNON_REL_MEASURAND		"measurand"
#define	SNON_REL_POWERED_BY		"powered_by"
#define	SNON_REL_TIMESYNC_BY	"timesync_by"
#define	SNON_REL_CONNETED_TO	"connected_to"
#define	SNON_REL_LOCATED_AT		"located_at"
#define	SNON_REL_MEASURED_FROM	"measured_from"
#define	SNON_REL_HEALTH			"health"
#define	SNON_REL_SETPOINT		"setpoint"
#define	SNON_REL_ALARMS			"alarms"
#define	SNON_REL_ALARM_INHIBIT	"alarm_inhibit"
#define	SNON_REL_INDETERMINATE	"indeterminate"
#define	SNON_REL_FLAG			"flag"
#define	SNON_REL_INTERRUPTS		"interrupts"
#define	SNON_REL_VALUES			"values"



