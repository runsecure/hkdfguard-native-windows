# A C ABI fuzz target's ctest run: every seed once, then up to RUNS inputs
# in all or MAX_TIME seconds, whichever comes first.
#
#   cmake -DFUZZER=<exe> -DSEEDS=<dir> -DFOUND=<dir> -DCRASHES=<dir>
#         -DRUNS=<n> -DMAX_TIME=<seconds> -P RunSmoke.cmake
#
# FOUND, where libFuzzer writes the inputs it discovers, is emptied first.
# libFuzzer replays everything in it before fuzzing, so a folder left to grow
# - by earlier runs, or by a long campaign pointed at it - makes this run
# slower every time; and inputs found without a KEK (not elevated) can each
# cost seconds once there is one. A smoke run starts from the seeds alone,
# so it takes the same time every time. Run the executable directly, with a
# corpus folder of your own, for a campaign (see README.md).
foreach(required FUZZER SEEDS FOUND CRASHES RUNS MAX_TIME)
    if(NOT DEFINED ${required})
        message(FATAL_ERROR "RunSmoke.cmake: -D${required}= is required")
    endif()
endforeach()

file(REMOVE_RECURSE "${FOUND}")
file(MAKE_DIRECTORY "${FOUND}" "${CRASHES}")

execute_process(
    COMMAND "${FUZZER}" -runs=${RUNS} -max_total_time=${MAX_TIME} -max_len=4096 -timeout=60
            "-artifact_prefix=${CRASHES}/" "${FOUND}" "${SEEDS}"
    RESULT_VARIABLE result)
if(NOT result EQUAL 0)
    message(FATAL_ERROR "${FUZZER} failed (${result}); a failing input, if any, is in ${CRASHES}")
endif()
