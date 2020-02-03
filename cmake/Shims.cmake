# LIST(JOIN ...) was introduced in CMake verison 3.12
macro(jss_list_join LIST_ SEPARATOR_ VAR_)
    if(${CMAKE_VERSION} VERSION_LESS "3.12.0")
        set("${VAR_}" "")
        foreach(ELEMENT ${${LIST_}})
            set("${VAR_}" "${${VAR_}}${SEPARATOR_}${ELEMENT}")
        endforeach()
        string(LENGTH "${SEPARATOR_}" JSS_LIST_JOIN_SEPARATOR_LENGTH)
        string(SUBSTRING "${${VAR_}}" ${JSS_LIST_JOIN_SEPARATOR_LENGTH} -1 "${VAR_}")
    else()
        list(JOIN ${LIST_} ${SEPARATOR_} ${VAR_})
    endif()
endmacro()

