#----------------------------------------------------------------
# Generated CMake target import file for configuration "Release".
#----------------------------------------------------------------

# Commands may need to know the format version.
set(CMAKE_IMPORT_FILE_VERSION 1)

# Import target "PALISADEcore" for configuration "Release"
set_property(TARGET PALISADEcore APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(PALISADEcore PROPERTIES
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/lib/libPALISADEcore.1.11.7.dylib"
  IMPORTED_SONAME_RELEASE "@rpath/libPALISADEcore.1.dylib"
  )

list(APPEND _IMPORT_CHECK_TARGETS PALISADEcore )
list(APPEND _IMPORT_CHECK_FILES_FOR_PALISADEcore "${_IMPORT_PREFIX}/lib/libPALISADEcore.1.11.7.dylib" )

# Import target "PALISADEpke" for configuration "Release"
set_property(TARGET PALISADEpke APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(PALISADEpke PROPERTIES
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/lib/libPALISADEpke.1.11.7.dylib"
  IMPORTED_SONAME_RELEASE "@rpath/libPALISADEpke.1.dylib"
  )

list(APPEND _IMPORT_CHECK_TARGETS PALISADEpke )
list(APPEND _IMPORT_CHECK_FILES_FOR_PALISADEpke "${_IMPORT_PREFIX}/lib/libPALISADEpke.1.11.7.dylib" )

# Import target "PALISADEbinfhe" for configuration "Release"
set_property(TARGET PALISADEbinfhe APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(PALISADEbinfhe PROPERTIES
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/lib/libPALISADEbinfhe.1.11.7.dylib"
  IMPORTED_SONAME_RELEASE "@rpath/libPALISADEbinfhe.1.dylib"
  )

list(APPEND _IMPORT_CHECK_TARGETS PALISADEbinfhe )
list(APPEND _IMPORT_CHECK_FILES_FOR_PALISADEbinfhe "${_IMPORT_PREFIX}/lib/libPALISADEbinfhe.1.11.7.dylib" )

# Commands beyond this point should not need to know the version.
set(CMAKE_IMPORT_FILE_VERSION)
