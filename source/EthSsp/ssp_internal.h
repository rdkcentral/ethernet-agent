/*
 * If not stated otherwise in this file or this component's Licenses.txt file the
 * following copyright and licenses apply:
 *
 * Copyright 2018 RDK Management
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
*/

/*********************************************************************************

    description:

        This is the template file of ssp_internal.h for XxxxSsp.
        Please replace "XXXX" with your own ssp name with the same up/lower cases.

    ------------------------------------------------------------------------------

    revision:

        09/08/2011    initial revision.

**********************************************************************************/

#ifndef  _SSP_INTERNAL_H_
#define  _SSP_INTERNAL_H_

#define  CCSP_COMMON_COMPONENT_HEALTH_Red                   1
#define  CCSP_COMMON_COMPONENT_HEALTH_Yellow                2
#define  CCSP_COMMON_COMPONENT_HEALTH_Green                 3

#define  CCSP_COMMON_COMPONENT_STATE_Initializing           1
#define  CCSP_COMMON_COMPONENT_STATE_Running                2
#define  CCSP_COMMON_COMPONENT_STATE_Blocked                3
#define  CCSP_COMMON_COMPONENT_STATE_Paused                 3

#define  CCSP_COMMON_COMPONENT_FREERESOURCES_PRIORITY_High  1
#define  CCSP_COMMON_COMPONENT_FREERESOURCES_PRIORITY_Low   2

#define  CCSP_COMPONENT_ID_ETHAGENT                             "com.cisco.spvtg.ccsp.ethagent"
#define  CCSP_COMPONENT_NAME_ETHAGENT                           "com.cisco.spvtg.ccsp.ethagent"
#define  CCSP_COMPONENT_VERSION_ETHAGENT                        1
#define  CCSP_COMPONENT_PATH_ETHAGENT                           "/com/cisco/spvtg/ccsp/ethagent"

typedef  struct
_COMPONENT_COMMON_ETHAGENT
{
    char*                           Name;
    ULONG                           Version;
    char*                           Author;
    ULONG                           Health;
    ULONG                           State;

    BOOL                            LogEnable;
    ULONG                           LogLevel;

    ULONG                           MemMaxUsage;
    ULONG                           MemMinUsage;
    ULONG                           MemConsumed;
}
COMPONENT_COMMON_ETHAGENT,  *PCOMPONENT_COMMON_ETHAGENT;

#define ComponentCommonDmInit(component_com_ethagent)                                          \
        {                                                                                  \
            AnscZeroMemory(component_com_ethagent, sizeof(COMPONENT_COMMON_ETHAGENT));             \
            component_com_ethagent->Name        = NULL;                                        \
            component_com_ethagent->Version     = 1;                                           \
            component_com_ethagent->Author      = NULL;                                        \
            component_com_ethagent->Health      = CCSP_COMMON_COMPONENT_HEALTH_Red;            \
            component_com_ethagent->State       = CCSP_COMMON_COMPONENT_STATE_Running;         \
            if(g_iTraceLevel >= CCSP_TRACE_LEVEL_EMERGENCY)                                \
                component_com_ethagent->LogLevel = (ULONG) g_iTraceLevel;                      \
            component_com_ethagent->LogEnable   = TRUE;                                        \
            component_com_ethagent->MemMaxUsage = 0;                                           \
            component_com_ethagent->MemMinUsage = 0;                                           \
            component_com_ethagent->MemConsumed = 0;                                           \
        }


#define  ComponentCommonDmClean(component_com_ethagent)                                        \
         {                                                                                  \
            if ( component_com_ethagent->Name )                                                \
            {                                                                               \
                AnscFreeMemory(component_com_ethagent->Name);                                  \
            }                                                                               \
                                                                                            \
            if ( component_com_ethagent->Author )                                              \
            {                                                                               \
                AnscFreeMemory(component_com_ethagent->Author);                                \
            }                                                                               \
         }


#define  ComponentCommonDmFree(component_com_ethagent)                                         \
         {                                                                                  \
            ComponentCommonDmClean(component_com_ethagent);                                    \
            AnscFreeMemory(component_com_ethagent);                                            \
         }

int  cmd_dispatch(int  command);


ANSC_STATUS
ssp_create
(
);

ANSC_STATUS
ssp_engage
(
);

ANSC_STATUS
ssp_cancel
(
);



char*
ssp_CcdIfGetComponentName
    (
        ANSC_HANDLE                     hThisObject
    );

ULONG
ssp_CcdIfGetComponentVersion
    (
        ANSC_HANDLE                     hThisObject
    );

char*
ssp_CcdIfGetComponentAuthor
    (
        ANSC_HANDLE                     hThisObject
    );

ULONG
ssp_CcdIfGetComponentHealth
    (
        ANSC_HANDLE                     hThisObject
    );

ULONG
ssp_CcdIfGetComponentState
    (
        ANSC_HANDLE                     hThisObject
    );

BOOL
ssp_CcdIfGetLoggingEnabled
    (
        ANSC_HANDLE                     hThisObject
    );

ANSC_STATUS
ssp_CcdIfSetLoggingEnabled
    (
        ANSC_HANDLE                     hThisObject,
        BOOL                            bEnabled
    );

ULONG
ssp_CcdIfGetLoggingLevel
    (
        ANSC_HANDLE                     hThisObject
    );

ANSC_STATUS
ssp_CcdIfSetLoggingLevel
    (
        ANSC_HANDLE                     hThisObject,
        ULONG                           LogLevel
    );

ULONG
ssp_CcdIfGetMemMaxUsage
    (
        ANSC_HANDLE                     hThisObject
    );

ULONG
ssp_CcdIfGetMemMinUsage
    (
        ANSC_HANDLE                     hThisObject
    );

ULONG
ssp_CcdIfGetMemConsumed
    (
        ANSC_HANDLE                     hThisObject
    );

ANSC_STATUS
ssp_CcdIfApplyChanges
    (
        ANSC_HANDLE                     hThisObject
    );


#endif
