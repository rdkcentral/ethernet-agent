/*
 * If not stated otherwise in this file or this component's Licenses.txt file the
 * following copyright and licenses apply:
 *
 * Copyright 2015 RDK Management
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

/**********************************************************************
   Copyright [2014] [Cisco Systems, Inc.]

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
**********************************************************************/


/***********************************************************************

    module: plugin_main_apis.c

        Implement COSA Data Model Library Init and Unload apis.
        This files will hold all data in it.

    ---------------------------------------------------------------

    description:

        This module implements the advanced state-access functions
        of the Dslh Var Record Object.

        *   CosaBackEndManagerCreate
        *   CosaBackEndManagerInitialize
        *   CosaBackEndManagerRemove
    ---------------------------------------------------------------

    author:

        COSA XML TOOL CODE GENERATOR 1.0

    ---------------------------------------------------------------

    revision:

        01/11/2011    initial revision.

**********************************************************************/
#include <syscfg/syscfg.h>
#include "plugin_main_apis.h"
#include "cosa_ethernet_apis.h"
#include "cosa_ethernet_internal.h"

#if  CFG_USE_Common_Util
#include "cosa_common_util.h"
#endif

#if defined(_PLATFORM_RASPBERRYPI_) || defined(_PLATFORM_BANANAPI_R4_)
extern int sock;
#endif

/**********************************************************************

    caller:     owner of the object

    prototype:

        ANSC_HANDLE
        CosaBackEndManagerCreate
            (
            );

    description:

        This function constructs cosa datamodel object and return handle.

    argument:

    return:     newly created nat object.

**********************************************************************/

ANSC_HANDLE
CosaBackEndManagerCreate
    (
        VOID
    )
{
    PCOSA_BACKEND_MANAGER_OBJECT    pMyObject    = (PCOSA_BACKEND_MANAGER_OBJECT)NULL;

    /*
        * We create object by first allocating memory for holding the variables and member functions.
        */
    pMyObject = (PCOSA_BACKEND_MANAGER_OBJECT)AnscAllocateMemory(sizeof(COSA_BACKEND_MANAGER_OBJECT));

    if ( !pMyObject )
    {
        return  (ANSC_HANDLE)NULL;
    }

    /*
     * Initialize the common variables and functions for a container object.
     */
    pMyObject->Oid               = COSA_DATAMODEL_BASE_OID;
    pMyObject->Create            = CosaBackEndManagerCreate;
    pMyObject->Remove            = CosaBackEndManagerRemove;
    pMyObject->Initialize        = CosaBackEndManagerInitialize;

    printf("-- %s %d\n", __func__, __LINE__);
    CcspTraceWarning(("RDKB_SYSTEM_BOOT_UP_LOG : Entering %s %d\n", __func__, __LINE__));

    return  (ANSC_HANDLE)pMyObject;
}

/**********************************************************************

    caller:     self

    prototype:

        ANSC_STATUS
        CosaBackEndManagerInitialize
            (
                ANSC_HANDLE                 hThisObject
            );

    description:

        This function initiate cosa manager object and return handle.

    argument:   ANSC_HANDLE                 hThisObject
            This handle is actually the pointer of this object
            itself.

    return:     operation status.

**********************************************************************/

ANSC_STATUS
CosaBackEndManagerInitialize
    (
        ANSC_HANDLE                 hThisObject
    )
{
    ANSC_STATUS                     returnStatus = ANSC_STATUS_SUCCESS;
    PCOSA_BACKEND_MANAGER_OBJECT  pMyObject    = (PCOSA_BACKEND_MANAGER_OBJECT)hThisObject;

#ifdef _COSA_SIM_
        pMyObject->has_moca_slap  = 0;
#endif

    /* Create all object */
    pMyObject->hEthernet      = (ANSC_HANDLE)CosaEthInterfaceCreate();
    AnscTraceWarning(("  CosaEthInterfaceCreate done!\n"));

    printf("CosaEthInferface initialization done!\n");

    return returnStatus;
}

/**********************************************************************

    caller:     self

    prototype:

        ANSC_STATUS
        CosaBackEndManagerRemove
            (
                ANSC_HANDLE                 hThisObject
            );

    description:

        This function remove cosa manager object and return handle.

    argument:   ANSC_HANDLE                 hThisObject
            This handle is actually the pointer of this object
            itself.

    return:     operation status.

**********************************************************************/

ANSC_STATUS
CosaBackEndManagerRemove
    (
        ANSC_HANDLE                 hThisObject
    )
{
    ANSC_STATUS                     returnStatus = ANSC_STATUS_SUCCESS;
    PCOSA_BACKEND_MANAGER_OBJECT  pMyObject    = (PCOSA_BACKEND_MANAGER_OBJECT)hThisObject;

    /* Remove all objects */

    if ( pMyObject->hEthernet )
    {
        CosaEthernetRemove((ANSC_HANDLE)pMyObject->hEthernet);
    }

    /* Remove self */
    AnscFreeMemory((ANSC_HANDLE)pMyObject);

    return returnStatus;
}
