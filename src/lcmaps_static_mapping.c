/***************************************************************
 *
 * Copyright (C) 2011, University of Nebraska-Lincoln
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you
 * may not use this file except in compliance with the License.  You may
 * obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 ***************************************************************/

/*
 * lcmaps_static_mapping.c
 * By Brian Bockelman, 2011 
 */

/*****************************************************************************
                            Include header files
******************************************************************************/

#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>

#include "lcmaps/lcmaps_modules.h"
#include "lcmaps/lcmaps_cred_data.h"
#include "lcmaps/lcmaps_arguments.h"

#include "static_mapping.h"
#include "proc_info.h"

#define PLUGIN_ARG "-mapfile"
#define DEFAULT_MAPFILE "/etc/grid-security/glexec-mapfile"

static const char * logstr = "static-mapping";
static char * mapfile = NULL;

int getGroupInfo(uid_t uid) {
  // Put in the group information.
  struct passwd *pw = getpwuid(uid);
  if (pw == NULL) {
    lcmaps_log(0, "%s: Unable to get username for target UID %d.\n", logstr, uid);
    return LCMAPS_MOD_FAIL;
  }
  lcmaps_log(3, "%s: Adding a primary GID %d.\n", logstr, pw->pw_gid);
  if (addCredentialData(PRI_GID, &(pw->pw_gid)) == -1) {
    lcmaps_log(0, "%s: Unable to add primary GID %d to credential data.", logstr, pw->pw_gid);
    return LCMAPS_MOD_FAIL;
  }
  int ng = 20;
  gid_t *groups = (gid_t *) malloc(ng*sizeof(gid_t));
  if (groups == NULL) {
    lcmaps_log(0, "%s: Unable to allocate memory for group list.\n", logstr);
    return LCMAPS_MOD_FAIL;
  }
  if (getgrouplist(pw->pw_name, pw->pw_gid, groups, &ng) < 0) {
    groups = (gid_t *) realloc(groups, ng * sizeof (gid_t));
    if (groups == NULL) {
      lcmaps_log(0, "%s: Unable to reallocate memory for group list.\n", logstr);
      return LCMAPS_MOD_FAIL;
    }
    if (getgrouplist(pw->pw_name, pw->pw_gid, groups, &ng) < 0) {
      lcmaps_log(0, "%s: Unable to lookup groups for user %s.\n", pw->pw_name);
      free(groups);
      return LCMAPS_MOD_FAIL;
    }
  }
  int idx;
  for (idx = 0; idx<ng; idx++) {
    lcmaps_log(3, "%s: Added a secondary GID: %d.\n", logstr, groups[idx]);
    if (addCredentialData(SEC_GID, &(groups[idx])) == -1) {
      lcmaps_log(0, "%s: Unable to add secondary GID %d to credential data.\n", logstr, groups[idx]);
    }
  }
  free(groups);

  return LCMAPS_MOD_SUCCESS;
}

/******************************************************************************
Function:   plugin_initialize
Description:
    Initialize plugin.
Parameters:
    argc, argv
    argv[0]: the name of the plugin
Returns:
    LCMAPS_MOD_SUCCESS : success
******************************************************************************/
int plugin_initialize(int argc, char **argv)
{

  int idx;
  mapfile = NULL;

  // Notice that we start at 1, as argv[0] is the plugin name.
  for (idx=1; idx<argc; argc++) {
    lcmaps_log_debug(2, "%s: arg %d is %s\n", logstr, idx, argv[idx]);
    if ((strncasecmp(argv[idx], PLUGIN_ARG, sizeof(PLUGIN_ARG)) == 0) && ((idx+1) < argc)) {
      if ((argv[idx+1] != NULL) && (strlen(argv[idx+1]) > 0)) {
        mapfile = strdup(argv[++idx]);
        if (mapfile == NULL) {
          lcmaps_log(0, "%s: String allocation error: %s\n", logstr, argv[idx-1]);
          return LCMAPS_MOD_FAIL;
        }
        lcmaps_log_debug(2, "%s: Mapfile is %s\n", logstr, mapfile);
      }
    } else {
      lcmaps_log(0, "%s: Invalid plugin option: %s\n", logstr, argv[idx]);
      return LCMAPS_MOD_FAIL;
    }
  }

  if (mapfile == NULL) {
    mapfile = strdup(DEFAULT_MAPFILE);
    if (mapfile == NULL) {
      lcmaps_log(0, "%s: String allocation error.\n", logstr);
      return LCMAPS_MOD_FAIL;
    }
  }

  return LCMAPS_MOD_SUCCESS;
}


/******************************************************************************
Function:   plugin_introspect
Description:
    return list of required arguments
Parameters:

Returns:
    LCMAPS_MOD_SUCCESS : success
******************************************************************************/
int plugin_introspect(int *argc, lcmaps_argument_t **argv)
{
  static lcmaps_argument_t argList[] = {
    {NULL        ,  NULL    , -1, NULL}
  };

  *argv = argList;
  *argc = lcmaps_cntArgs(argList);

  return LCMAPS_MOD_SUCCESS;
}




/******************************************************************************
Function:   plugin_run
Description:
    Create bind mounts for the glexec'd process
    Heavy lifting is done in C++.
Parameters:
    argc: number of arguments
    argv: list of arguments
Returns:
    LCMAPS_MOD_SUCCESS: authorization succeeded
    LCMAPS_MOD_FAIL   : authorization failed
******************************************************************************/
int plugin_run(int argc, lcmaps_argument_t *argv)
{
  uid_t uid;
  pid_t ppid, ppid2;
  gid_t gid;

  pid_t pid = getpid();

  if (mapfile == NULL) {
    lcmaps_log(0, "%s: Plugin initialization failed.\n", logstr);
    return LCMAPS_MOD_FAIL;
  }

  // First, get my parent.
  if (get_proc_info(pid, NULL, NULL, &ppid)) {
    lcmaps_log(0, "%s: Unable to get my parent PID info.\n", logstr);
    return LCMAPS_MOD_FAIL;
  }

  // Then, get my parent's UID/GID.
  if (get_proc_info(ppid, &uid, &gid, NULL)) {
    lcmaps_log(0, "%s: Unable to get parent's UID/GID.\n", logstr);
    return LCMAPS_MOD_FAIL;
  }

  // To eliminate race conditions, verify that the parent PID hasn't changed.
  if (get_proc_info(pid, NULL, NULL, &ppid2)) {
    lcmaps_log(0, "%s: Unable to verify parent PID.\n", logstr);
    return LCMAPS_MOD_FAIL;
  }

  if (ppid != ppid2) {
    lcmaps_log(0, "%s: Parent PID check failed (now %d, was %d).\n", logstr, ppid2, ppid);
    return LCMAPS_MOD_FAIL;
  }

  // Map the UID based on the mapfile.
  uid_t target_uid;
  if ((target_uid = getMappedUID(uid, mapfile)) == -1) {
    lcmaps_log(3, "%s: Unable to map %d; module failure.\n", logstr, uid);
    return LCMAPS_MOD_FAIL;
  }
  lcmaps_log(3,"%s: Static mapping of %d -> %d.\n", logstr, uid, target_uid);
  if (addCredentialData(UID, &target_uid) == -1) {
    lcmaps_log(0, "%s: Unable to add UID %d to credential data.\n", logstr, target_uid);
    return LCMAPS_MOD_FAIL;
  }

  return getGroupInfo(target_uid);

}

int plugin_verify(int argc, lcmaps_argument_t * argv)
{
    return plugin_run(argc, argv);
}

/******************************************************************************
Function:   plugin_terminate
Description:
    Terminate plugin.  Boilerplate - doesn't do anything
Parameters:

Returns:
    LCMAPS_MOD_SUCCESS : success
******************************************************************************/
int plugin_terminate()
{
  if (mapfile) {
    free(mapfile);
    mapfile = NULL;
  }
  return LCMAPS_MOD_SUCCESS;
}
