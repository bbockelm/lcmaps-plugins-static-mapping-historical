
#include <stdio.h>
#include <errno.h>
#include <limits.h>
#include <string.h>
#include <pwd.h>
#include "static_mapping.h"

#include <boost/tokenizer.hpp>

extern "C" {
#include <lcmaps/lcmaps_log.h>
}

static const char * logstr = "static-mapping";

uid_t getMappedUID(uid_t uid, const char * mapfile) {

  FILE *fp = NULL;

  struct passwd *pwd_entry;
  while (((pwd_entry = getpwuid(uid)) == NULL) && (errno == EINTR)) {}
  if (pwd_entry == NULL) {
    lcmaps_log(0, "%s: Unable to lookup username for UID %d: (errno=%d) %s.\n", logstr, uid, errno, strerror(errno));
    return -1;
  }

  if ((fp = fopen(mapfile, "r")) == NULL) {
    lcmaps_log(0, "%s: Unable to open mapfile %s: (errno=%d) %s.\n", logstr, mapfile, errno, strerror(errno));
    return -1;
  }

  std::string parent_str(pwd_entry->pw_name);
  std::string target_str;
  bool match = false;

  char buf[LINE_MAX];
  while ((fgets(buf, LINE_MAX, fp)) != NULL) {

    // Ignore comment lines
    if (strchr(buf, '#') != NULL) {
      continue;
    }

    std::string s(buf);
    boost::tokenizer<> tokens(s);
    bool found_token_1 = false, found_token_2 = false;

    for(boost::tokenizer<>::const_iterator it = tokens.begin(); it != tokens.end(); ++it) {
      std::string token = *it;
      if ((token)[0] == '#') {
        break;
      }
      if (found_token_1 == false) {
        found_token_1 = true;
        match = (token == parent_str);
      } else if (found_token_2 == false) {
        target_str = token;
        found_token_2 = true;
      } else {
        lcmaps_log(0, "%s: Invalid line in mapfile: %s", logstr, buf);
        match = false;
      }
    }
    if (found_token_1 && !found_token_2) {
      lcmaps_log(0, "%s: Invalid line in mapfile: %s", logstr, buf);
      continue;
    }
    if (match) {
      break;
    }
  }

  if (!feof(fp) && ferror(fp)) {
    lcmaps_log(0, "%s: Error reading from mapfile %s: (errno=%d) %s.\n", logstr, mapfile, errno, strerror(errno));
    fclose(fp);
    return -1;
  }
  fclose(fp);

  if (!match) {
    lcmaps_log(3, "%s: No mapping for user %s.\n", logstr, parent_str.c_str());
    return -1;
  }

  while (((pwd_entry = getpwnam(target_str.c_str())) == NULL) && (errno == EINTR)) {}
  if (pwd_entry == NULL) {
    lcmaps_log(0, "%s: Unable to lookup UID for user %s: (errno=%d) %s.\n",
      logstr, target_str.c_str(), errno, strerror(errno));
  }

  return pwd_entry->pw_uid;

}

