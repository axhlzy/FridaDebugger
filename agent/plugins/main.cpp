#include <android/log.h>
#include <time.h>

#include "fridaBind.h"

int main() {
  time_t now = time(0);
  tm *ltm = localtime(&now);
  __android_log_print(ANDROID_LOG_INFO, "time", "%d-%d-%d %d:%d:%d",
                      1900 + ltm->tm_year, 1 + ltm->tm_mon, ltm->tm_mday,
                      ltm->tm_hour, ltm->tm_min, ltm->tm_sec);
  return 0;
}

/********************************************************************************************/

#include <LIEF/ART.hpp>
#include <LIEF/logging.hpp>
#include <iostream>
#include <memory>

using namespace LIEF::ART;

extern "C" int test_lief(const char *soPath) {
  LIEF::logging::set_level(LIEF::logging::LOGGING_LEVEL::LOG_DEBUG);
  auto binary = Parser::parse(soPath);
  if (binary == nullptr) {
    frida_log("Failed to parse binary");
    return 1;
  } else {
    frida_log("Parsed binary success");
    return 0;
  }
}