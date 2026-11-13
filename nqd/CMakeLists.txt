# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# nqd, the data layer (include/nqd.h): a library of its own on the
# public API of noqtis only, outside the audited core. Static or shared
# as noqtis is; its symbols hidden but those nqd.h marks NQDAPI.
file(GLOB NQDSRC CONFIGURE_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/*.c)
if(NQSHARED)
  add_library(nqd SHARED ${NQDSRC})
  set_target_properties(nqd PROPERTIES
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR})
  if(WIN32)
    set_target_properties(nqd PROPERTIES PREFIX ""
      RUNTIME_OUTPUT_NAME nqd-${PROJECT_VERSION_MAJOR})
    target_compile_definitions(nqd PRIVATE NQDLL INTERFACE NQDLL)
  endif()
else()
  add_library(nqd STATIC ${NQDSRC})
endif()
add_library(noqtis::nqd ALIAS nqd)
target_link_libraries(nqd PUBLIC noqtis)
target_compile_definitions(nqd PRIVATE NQDBUILD)
target_compile_options(nqd PRIVATE ${NQWARN})
target_include_directories(nqd PUBLIC
  $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
  $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)
set_target_properties(nqd PROPERTIES C_VISIBILITY_PRESET hidden
  POSITION_INDEPENDENT_CODE ${NQSHARED})
if(NOT WIN32)
  target_link_libraries(nqd PRIVATE m)
endif()
install(TARGETS nqd EXPORT noqtisTargets
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
install(FILES ${PROJECT_SOURCE_DIR}/include/nqd.h
  DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
