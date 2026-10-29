# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# The noqtis command-line tool: the public API only, linked against the
# library as built (static or shared).
file(GLOB NQCSRC CONFIGURE_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/*.c)
add_executable(nqcli ${NQCSRC})
# bin/ keeps noqtis(.exe) apart from the library's own files (noqtis.lib,
# noqtis.pdb on Windows)
set_target_properties(nqcli PROPERTIES OUTPUT_NAME noqtis
  RUNTIME_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/bin)
target_link_libraries(nqcli PRIVATE noqtis)
# the TSA client resolves names on a thread, so the lookup has a deadline
if(NOT WIN32)
  set(THREADS_PREFER_PTHREAD_FLAG ON)
  find_package(Threads REQUIRED)
  target_link_libraries(nqcli PRIVATE Threads::Threads)
endif()
target_compile_options(nqcli PRIVATE ${NQWARN})
if(WIN32)
  target_link_libraries(nqcli PRIVATE shell32 ws2_32)
  if(NQSHARED)
    # the DLL beside the tool, so it runs from the build tree
    add_custom_command(TARGET nqcli POST_BUILD
      COMMAND ${CMAKE_COMMAND} -E copy_if_different
              $<TARGET_FILE:noqtis> $<TARGET_FILE_DIR:nqcli>)
  endif()
endif()
install(TARGETS nqcli RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
# the shell completions (completions/), where bash-completion, zsh and
# fish look for them
if(NOT WIN32)
  install(FILES completions/noqtis.bash RENAME noqtis
    DESTINATION ${CMAKE_INSTALL_DATADIR}/bash-completion/completions)
  install(FILES completions/_noqtis
    DESTINATION ${CMAKE_INSTALL_DATADIR}/zsh/site-functions)
  install(FILES completions/noqtis.fish
    DESTINATION ${CMAKE_INSTALL_DATADIR}/fish/vendor_completions.d)
endif()
