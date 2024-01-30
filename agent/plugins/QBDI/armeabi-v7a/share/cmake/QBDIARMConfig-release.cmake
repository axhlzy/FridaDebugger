#----------------------------------------------------------------
# Generated CMake target import file for configuration "Release".
#----------------------------------------------------------------

# Commands may need to know the format version.
set(CMAKE_IMPORT_FILE_VERSION 1)

# Import target "QBDI::ARM::QBDI_static" for configuration "Release"
set_property(TARGET QBDI::ARM::QBDI_static APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(QBDI::ARM::QBDI_static PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_RELEASE "C"
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/lib/libQBDI.a"
  )

list(APPEND _cmake_import_check_targets QBDI::ARM::QBDI_static )
list(APPEND _cmake_import_check_files_for_QBDI::ARM::QBDI_static "${_IMPORT_PREFIX}/lib/libQBDI.a" )

# Import target "QBDI::ARM::QBDI" for configuration "Release"
set_property(TARGET QBDI::ARM::QBDI APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(QBDI::ARM::QBDI PROPERTIES
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/lib/libQBDI.so"
  IMPORTED_SONAME_RELEASE "libQBDI.so"
  )

list(APPEND _cmake_import_check_targets QBDI::ARM::QBDI )
list(APPEND _cmake_import_check_files_for_QBDI::ARM::QBDI "${_IMPORT_PREFIX}/lib/libQBDI.so" )

# Commands beyond this point should not need to know the version.
set(CMAKE_IMPORT_FILE_VERSION)
