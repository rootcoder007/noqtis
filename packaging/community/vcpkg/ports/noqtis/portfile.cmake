vcpkg_from_github(
    OUT_SOURCE_PATH SOURCE_PATH
    REPO rootcoder007/noqtis
    REF "v${VERSION}"
    SHA512 d8b290642c8f0cab6a6d90d3a855b8beaae88e7d27ea2b9a6d2ff5991f100a37625502a2112440dc1f03961494843ca8dc7e9d6bd578f9de19b3ead1c5edf64f
    HEAD_REF main
)

string(COMPARE EQUAL "${VCPKG_LIBRARY_LINKAGE}" "dynamic" NQSHARED)

vcpkg_check_features(OUT_FEATURE_OPTIONS FEATURE_OPTIONS
    FEATURES
        tool NQCLI
)

vcpkg_cmake_configure(
    SOURCE_PATH "${SOURCE_PATH}"
    OPTIONS
        ${FEATURE_OPTIONS}
        -DNQSHARED=${NQSHARED}
        -DNQTESTS=OFF
        -DNQWERROR=OFF
        -DNQMAN=OFF
)

vcpkg_cmake_install()
vcpkg_cmake_config_fixup(CONFIG_PATH lib/cmake/noqtis)
vcpkg_fixup_pkgconfig()

if("tool" IN_LIST FEATURES)
    vcpkg_copy_tools(TOOL_NAMES noqtis AUTO_CLEAN)
endif()

file(REMOVE_RECURSE
    "${CURRENT_PACKAGES_DIR}/debug/include"
    "${CURRENT_PACKAGES_DIR}/debug/share"
    "${CURRENT_PACKAGES_DIR}/share/doc"
)

file(INSTALL "${CMAKE_CURRENT_LIST_DIR}/usage" DESTINATION "${CURRENT_PACKAGES_DIR}/share/${PORT}")
vcpkg_install_copyright(FILE_LIST "${SOURCE_PATH}/LICENSE" "${SOURCE_PATH}/NOTICE")
