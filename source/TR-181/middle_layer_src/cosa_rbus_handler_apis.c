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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "ccsp_trace.h"
#include "cosa_rbus_handler_apis.h"
//#include <sysevent/sysevent.h>
#include "syscfg/syscfg.h"

#if  defined  (WAN_FAILOVER_SUPPORTED) ||  defined(RBUS_BUILD_FLAG_ENABLE) || defined (_HUB4_PRODUCT_REQ_) || defined (_PLATFORM_RASPBERRYPI_) ||  defined(_PLATFORM_BANANAPI_R4_)
rbusHandle_t handle;
#endif

#if defined (WAN_FAILOVER_SUPPORTED)
EthAgent_Link_Status ethAgent_Link_Status;

unsigned int gSubscribersCount = 0;

/***********************************************************************

  Data Elements declaration:

 ***********************************************************************/
rbusDataElement_t ethAgentRbusDataElements[] = {

    {ETHWAN_LINK_STATUS_TR181, RBUS_ELEMENT_TYPE_EVENT, {getBoolHandler, NULL, NULL, NULL, eventSubHandler, NULL}},
    {ETHWAN_LINK_DOWN_TR181, RBUS_ELEMENT_TYPE_EVENT, {getBoolHandler, setBoolHandler, NULL, NULL, NULL, NULL}},
    {ETHWAN_LINK_DOWN_TIMEOUT_TR181, RBUS_ELEMENT_TYPE_EVENT, {getuintHandler, setuintHandler, NULL, NULL, NULL, NULL}},

};

#define NUM_OF_RBUS_PARAMS sizeof(ethAgentRbusDataElements)/sizeof(ethAgentRbusDataElements[0])

BOOL Rbus_EthAgent_SetParamBoolValue(void* hInsContext, char* pParamName, BOOL bValue);
BOOL Rbus_EthAgent_SetParamUintValue(void* hInsContext, char* pParamName, uint uValue);

/***********************************************************************

  Get Handler APIs for objects of type RBUS_BOOL:

 ***********************************************************************/
rbusError_t getBoolHandler(rbusHandle_t handle, rbusProperty_t property, rbusGetHandlerOptions_t *opts)
{
	char const *name = rbusProperty_GetName(property);
	(void)handle;
	(void)opts;
	rbusValue_t value;
	rbusValue_Init(&value);

	if (strcmp(name, ETHWAN_LINK_STATUS_TR181) == 0)
	{
		CcspTraceWarning(("Getting EWAN link status value, new value = '%d'\n", ethAgent_Link_Status.EWanLinkStatus));
		rbusValue_SetBoolean(value, ethAgent_Link_Status.EWanLinkStatus);
	}
	else if (strcmp(name, ETHWAN_LINK_DOWN_TR181) == 0)
	{
		CcspTraceWarning(("Getting EWAN link down value, new value = '%d'\n", ethAgent_Link_Status.EWanLinkDown));
		rbusValue_SetBoolean(value, ethAgent_Link_Status.EWanLinkDown);
	}
	else
	{
		CcspTraceWarning(("EthAgent rbus get handler invalid input\n"));
		return RBUS_ERROR_INVALID_INPUT;
	}
	rbusProperty_SetValue(property, value);
	rbusValue_Release(value);

	return RBUS_ERROR_SUCCESS;
}

/***********************************************************************

  Set Handler API for objects of type RBUS_BOOLEAN for objects:

 **********************************************************************/
rbusError_t setBoolHandler(rbusHandle_t handle, rbusProperty_t property, rbusSetHandlerOptions_t *opts)
{
	UNREFERENCED_PARAMETER(handle);
	UNREFERENCED_PARAMETER(opts);

	bool rc = false;
	char const* propName = rbusProperty_GetName(property);
	CcspTraceWarning(("%s called for propName='%s'\n", __FUNCTION__, propName));
	char *param = strdup(GetParamName(propName));
	rbusValue_t value = rbusProperty_GetValue(property);

	if (param == NULL)
	{
		CcspTraceWarning(("%s strdup failed\n", __FUNCTION__));
		return RBUS_ERROR_BUS_ERROR;
	}

	CcspTraceWarning(("%s called for param='%s'\n", __FUNCTION__, param));

	if (value)
	{
		if (rbusValue_GetType(value) == RBUS_BOOLEAN)
		{
			rc = Rbus_EthAgent_SetParamBoolValue(NULL, param, rbusValue_GetBoolean(value));
			free(param);
			if (!rc)
			{
				CcspTraceWarning(("%s Set ETHWAN_LINKDOWN_TR181 param failed\n", __FUNCTION__));
				return RBUS_ERROR_BUS_ERROR;
			}
			return RBUS_ERROR_SUCCESS;
		}
		else
		{
			CcspTraceWarning(("%s result:FAIL error:'unexpected type %d'\n", __FUNCTION__, rbusValue_GetType(value)));
		}
	}
	else
	{
		CcspTraceWarning(("%s result:FAIL value=NULL param='%s'\n", __FUNCTION__, param));
	}

	free(param);
	return RBUS_ERROR_BUS_ERROR;
}

/***********************************************************************

  Get Handler APIs for objects of type RBUS_UINT:

 ***********************************************************************/
rbusError_t getuintHandler(rbusHandle_t handle, rbusProperty_t property, rbusGetHandlerOptions_t *opts)
{
	UNREFERENCED_PARAMETER(handle);
	UNREFERENCED_PARAMETER(opts);

	char const *name = rbusProperty_GetName(property);
	char ParamValue[16];
	rbusValue_t value;
	rbusValue_Init(&value);

	if (strcmp(name, ETHWAN_LINK_DOWN_TIMEOUT_TR181) == 0)
	{
		syscfg_get(NULL, ETHWAN_LINK_DOWN_TIMEOUT, ParamValue, sizeof(ParamValue));
		ethAgent_Link_Status.EWanLinkDownTimeout = atoi(ParamValue);
		CcspTraceWarning(("Getting EthWAN link Down TimeOut value = '%d'\n", ethAgent_Link_Status.EWanLinkDownTimeout));
		rbusValue_SetUInt32(value, ethAgent_Link_Status.EWanLinkDownTimeout);
	}
	else
	{
		CcspTraceWarning(("EthAgent rbus get handler invalid input\n"));
		return RBUS_ERROR_INVALID_INPUT;
	}
	rbusProperty_SetValue(property, value);
	rbusValue_Release(value);

	return RBUS_ERROR_SUCCESS;
}

/***********************************************************************

 Set Handler API for objects of type RBUS_UINT for objects:

***********************************************************************/
rbusError_t setuintHandler(rbusHandle_t handle, rbusProperty_t property, rbusSetHandlerOptions_t* opts)
{
	UNREFERENCED_PARAMETER(handle);
	UNREFERENCED_PARAMETER(opts);

	bool rc = false;
	char const* propName = rbusProperty_GetName(property);
	char* param = strdup(GetParamName(propName));
	rbusValue_t value = rbusProperty_GetValue(property);

	if (param == NULL)
	{
		CcspTraceWarning(("%s strdup failed\n", __FUNCTION__));
		return RBUS_ERROR_BUS_ERROR;
	}

	CcspTraceWarning(("%s called for param='%s'\n", __FUNCTION__, param));

	if (value)
	{
		if (rbusValue_GetType(value) == RBUS_UINT32)
		{
			rc = Rbus_EthAgent_SetParamUintValue(NULL, param, (uint)rbusValue_GetUInt32(value));
			free(param);
			if (!rc)
			{
				CcspTraceWarning(("Set ETHWAN_LINK_DOWN_TIMEOUT_TR181 failed\n"));
				return RBUS_ERROR_BUS_ERROR;
			}
			return RBUS_ERROR_SUCCESS;
		}
		else
		{
			CcspTraceWarning(("%s result:FAIL error:'unexpected type %d'\n", __FUNCTION__, rbusValue_GetType(value)));
		}
        }
	else
	{
		CcspTraceWarning(("%s result:FAIL value=NULL param='%s'\n", __FUNCTION__, param));
	}

	free(param);

	return RBUS_ERROR_BUS_ERROR;
}

/***********************************************************************

  Event subscribe handler API for objects:

 ***********************************************************************/
rbusError_t eventSubHandler(rbusHandle_t handle, rbusEventSubAction_t action, const char *eventName, rbusFilter_t filter, int32_t interval, bool *autoPublish)
{
	(void)handle;
	(void)filter;
	(void)interval;

	*autoPublish = false;

	if (!strcmp(ETHWAN_LINK_STATUS_TR181, eventName))
	{
		if (action == RBUS_EVENT_ACTION_SUBSCRIBE)
		{
			gSubscribersCount += 1;
		}
		else
		{
			if (gSubscribersCount > 0)
			{
				gSubscribersCount -= 1;
			}
		}
		CcspTraceWarning(("Subscribers count changed, new value=%d\n", gSubscribersCount));
	}
	else
	{
		CcspTraceWarning(("provider: eventSubHandler unexpected eventName %s\n", eventName));
	}
	return RBUS_ERROR_SUCCESS;
}

/*******************************************************************************

  Set Eth agent bool parameters

 ********************************************************************************/
BOOL Rbus_EthAgent_SetParamBoolValue(void* hInsContext, char* pParamName, BOOL bValue)
{
	UNREFERENCED_PARAMETER(hInsContext);

	CcspTraceInfo(("%s pParamName = %s, bValue = %d\n", __FUNCTION__, pParamName, bValue));
	if (strcmp(pParamName, "LinkDown") == 0)
	{
		if (ethAgent_Link_Status.EWanLinkDown!=bValue)
		{
			ethAgent_Link_Status.EWanLinkDown = bValue;
                        if (ethAgent_Link_Status.pEWanLinkDownSignal!=NULL)
			{
				ethAgent_Link_Status.pEWanLinkDownSignal();
			}
			else
			{
				CcspTraceInfo(("%s function address is not assigned to pEWanLinkDownSignal\n", __FUNCTION__));
			}
			CcspTraceInfo(("%s : parameter name = '%s', value = '%d'\n", __FUNCTION__,
					pParamName, ethAgent_Link_Status.EWanLinkDown));
			return TRUE;
		}
		else
		{
			CcspTraceInfo(("%s : trying to set same value for parameter '%s', value is '%d'\n",
					__FUNCTION__, pParamName, ethAgent_Link_Status.EWanLinkDown));
			return FALSE;
		}
	}
	CcspTraceInfo(("Unsupported parameter '%s'\n", pParamName));

	return FALSE;
}
/*******************************************************************************

 set the CM agent uint parameters

 ********************************************************************************/
BOOL Rbus_EthAgent_SetParamUintValue(void* hInsContext, char* pParamName, uint uValue)
{
	UNREFERENCED_PARAMETER(hInsContext);
	CcspTraceInfo(("%s pParamName = %s, uValue = %d\n", __FUNCTION__, pParamName, uValue));
	if (strcmp(pParamName, "LinkDownTimeout") == 0)
	{
		if (ethAgent_Link_Status.EWanLinkDownTimeout != uValue)
		{
			ethAgent_Link_Status.EWanLinkDownTimeout = uValue;
			syscfg_set_u_commit(NULL, ETHWAN_LINK_DOWN_TIMEOUT, ethAgent_Link_Status.EWanLinkDownTimeout);
			CcspTraceInfo(("%s : parameter name ='%s', value = '%d'\n",
					__FUNCTION__, pParamName, ethAgent_Link_Status.EWanLinkDownTimeout));
			return TRUE;
		}
		else
		{
			CcspTraceWarning(("%s trying to set same value for parameter '%s', value is '%d' \n",
					__FUNCTION__, pParamName, ethAgent_Link_Status.EWanLinkDownTimeout));
			return FALSE;
		}
	}
	CcspTraceInfo(("Unsupported parameter '%s'\n", pParamName));
	return FALSE;
}

/*******************************************************************************

 GetParamName from arg and return parameter name

 ********************************************************************************/
char const* GetParamName(char const* path)
{
	char const* p = path + strlen(path);
	while (p > path && *(p-1) != '.')
	{
		p--;
	}

	return p;
}

/*******************************************************************************

  initLinkStatus(): Initialize EthAgent_Link_Status struct with default values

 ********************************************************************************/
void initLinkStatus()
{
    char ParamValue[16];

    ethAgent_Link_Status.EWanLinkStatus = false;
    ethAgent_Link_Status.EWanLinkDown = false;
    if (!syscfg_get(NULL, ETHWAN_LINK_DOWN_TIMEOUT, ParamValue, sizeof(ParamValue)))
    {
	    ethAgent_Link_Status.EWanLinkDownTimeout = atoi(ParamValue);
	    CcspTraceWarning(("Initialized EWanLinkDownTimeout:%d\n", ethAgent_Link_Status.EWanLinkDownTimeout));
    }
    CcspTraceWarning(("Initialized EWAN link status with default values.\n"));
}


/*******************************************************************************

  sendUpdateEvent(): publish event after event value gets updated

 ********************************************************************************/
rbusError_t sendBoolUpdateEvent(char* event_name , bool eventNewData, bool eventOldData)
{
	rbusEvent_t event;
	rbusObject_t data;
	rbusValue_t value;
	rbusValue_t oldVal;
	rbusValue_t byVal;
	rbusError_t ret = RBUS_ERROR_SUCCESS;
	
	//initialize and set previous value for the event
	rbusValue_Init(&oldVal);
	rbusValue_SetBoolean(oldVal, eventOldData);
	//initialize and set new value for the event
	rbusValue_Init(&value);
	rbusValue_SetBoolean(value, eventNewData);
	//initialize and set responsible component name for value change
	rbusValue_Init(&byVal);
	rbusValue_SetString(byVal, RBUS_COMPONENT_NAME);
	//initialize and set rbusObject with desired values
	rbusObject_Init(&data, NULL);
	rbusObject_SetValue(data, "value", value);
	rbusObject_SetValue(data, "oldValue", oldVal);
	rbusObject_SetValue(data, "by", byVal);
	//set data to be transferred
	event.name = event_name;
	event.data = data;
	event.type = RBUS_EVENT_VALUE_CHANGED;
	//publish the event
	ret = rbusEvent_Publish(handle, &event);
	if(ret != RBUS_ERROR_SUCCESS) {
			CcspTraceWarning(("rbusEvent_Publish for %s failed: %d\n", event_name, ret));
	}
	//release all initialized rbusValue objects
	rbusValue_Release(value);
	rbusValue_Release(oldVal);
	rbusValue_Release(byVal);
	rbusObject_Release(data);
	return ret;
}

/*******************************************************************************

  publishEWanLinkStatus(): publish EWanLinkStatus event after event value gets updated

 ********************************************************************************/
 
void publishEWanLinkStatus(bool link_status)
{
	rbusError_t ret = RBUS_ERROR_SUCCESS;
	bool oldEWanLinkStatus = ethAgent_Link_Status.EWanLinkStatus;
	//update EWanLinkStatus with new value
	ethAgent_Link_Status.EWanLinkStatus = link_status;
	CcspTraceInfo(("Publishing EWAN link status with updated value=%s\n", ethAgent_Link_Status.EWanLinkStatus ? "true" : "false"));
	if (gSubscribersCount > 0)
	{
		ret = sendBoolUpdateEvent(ETHWAN_LINK_STATUS_TR181, ethAgent_Link_Status.EWanLinkStatus, oldEWanLinkStatus);
		if(ret == RBUS_ERROR_SUCCESS) {
			CcspTraceInfo(("Published EWAN link status with updated value.\n"));
		}
		
	}
}
#endif //WAN_FAILOVER_SUPPORTED

#if defined (_HUB4_PRODUCT_REQ_) || defined (_PLATFORM_RASPBERRYPI_) ||  defined(_PLATFORM_BANANAPI_R4_)
BOOL EthAgent_Rbus_discover_components(char const *pModuleList)
{
    rbusError_t rc = RBUS_ERROR_SUCCESS;
    int componentCnt = 0;
    char **pComponentNames;
    BOOL ret = FALSE;
    char ModuleList[1024] = {0};
    char const *rbusModuleList[7];
    int count = 0;
    const char delimit[2] = " ";
    char *token;

    strcpy(ModuleList,pModuleList);

    /* get the first token */
    token = strtok(ModuleList, delimit);

    /* walk through other tokens */
    while( token != NULL ) {
        printf( " %s\n", token );
        rbusModuleList[count]=token;
        count++;
        token = strtok(NULL, delimit);
    }

    for(int i=0; i<count;i++)
    {
        CcspTraceInfo(("EthAgent_Rbus_discover_components rbusModuleList[%s]\n", rbusModuleList[i]));
    }

    rc = rbus_discoverComponentName (handle, count, rbusModuleList, &componentCnt, &pComponentNames);

    if(RBUS_ERROR_SUCCESS != rc)
    {
        CcspTraceInfo(("Failed to discover components. Error Code = %d\n", rc));
        return ret;
    }

    for (int i = 0; i < componentCnt; i++)
    {
        free(pComponentNames[i]);
    }

    free(pComponentNames);

    if(componentCnt == count)
    {
        ret = TRUE;
    }

    CcspTraceInfo( ("EthAgent_Rbus_discover_components (%d-%d)ret[%s]\n",componentCnt,count,(ret)?"TRUE":"FALSE"));

    return ret;
}

#endif //_HUB4_PRODUCT_REQ_

#if  defined  (WAN_FAILOVER_SUPPORTED) ||  defined(RBUS_BUILD_FLAG_ENABLE) || defined (_HUB4_PRODUCT_REQ_) || defined(_PLATFORM_RASPBERRYPI_) ||  defined(_PLATFORM_BANANAPI_R4_)
/***********************************************************************

  ethAgentRbusInit(): Initialize Rbus and data elements

 ***********************************************************************/
rbusError_t ethAgentRbusInit()
{
	int rc = RBUS_ERROR_SUCCESS;
	rc = rbus_open(&handle, RBUS_COMPONENT_NAME);
	if (rc != RBUS_ERROR_SUCCESS)
	{
		CcspTraceWarning(("EthAgent rbus initialization failed\n"));
		rc = RBUS_ERROR_NOT_INITIALIZED;
		return rc;
	}

#if  defined  (WAN_FAILOVER_SUPPORTED)
	// Register data elements
	rc = rbus_regDataElements(handle, NUM_OF_RBUS_PARAMS, ethAgentRbusDataElements);
#endif

	if (rc != RBUS_ERROR_SUCCESS)
	{
		CcspTraceWarning(("rbus register data elements failed\n"));
		rc = rbus_close(handle);
		return rc;
	}

#if  defined  (WAN_FAILOVER_SUPPORTED)	
	initLinkStatus();
#endif

	return rc;
}
#endif
