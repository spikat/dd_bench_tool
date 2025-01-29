#!/bin/bash
set -uo pipefail
shopt -s globstar

NEEDED_UTILS="ip iperf3 jq nice taskset cset"

SYSPROBE_PATH="./system-probe"
SYSPROBE_LOG="system-probe.log"
SYSPROBE_PID="system-probe.pid"

NS1="ns1"
NS2="ns2"
IFACE1="veth1"
IFACE2="veth2"
IP1="192.168.1.1"
IP2="192.168.1.2"

# CPU CONFIGURATION
# First, check thread siblings:
# $> cat /sys/devices/system/cpu/cpu*/topology/thread_siblings_list|sort|uniq
# for ex:
#   0,8
#   1,9
#   2,10
#   3,11
#   4,12
#   5,13
#   6,14
#   7,15
# Then, select 3 cores (one for the server, one for the client, one for sysprobe):
CPU_ISOLATED="5-7"
CPU_SERVER=5
CPU_CLIENT=6
CPU_SYSPROBE=7
CPU_OTHERS="0-4,8-15"
# Set also the related siblings to disable them from being scheduled:
CPU_SIBLINGS="13 14 15"

# TODO: SET TO cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor
# Possible values: cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_available_governors
INITIAL_SCALING_GOV=powersave

die() {
    echo "ERROR: $1"
    # cleanup
    exit 1
}

cleanup() {
    echo cleanup
    unset_ifaces
    unset_system
    echo cleanup done
}

is_cgroup_v2() {
    local fs_type=$(stat -fc %T /sys/fs/cgroup/)
    if [ "$fs_type" = "cgroup2fs" ]; then
        return 0
    elif [ "$fs_type" = "tmpfs" ]; then
        return 1
    else
        die "Unknown cgroup version"
    fi
}

reset_cpu_cgroupv2() {
    echo "reset cpu isolation"
    echo member > /sys/fs/cgroup/shield/cpuset.cpus.partition || :
    rmdir /sys/fs/cgroup/shield
}

isolate_cpu_cgroupv2() {
    echo "isolate cpu for cgroup v2"
    mkdir -p /sys/fs/cgroup/shield
    echo "+cpu"    >> /sys/fs/cgroup/cgroup.subtree_control
    echo "+cpuset" >> /sys/fs/cgroup/cgroup.subtree_control
    echo "$CPU_ISOLATED" > /sys/fs/cgroup/shield/cpuset.cpus
    for cpscpus in /sys/fs/cgroup/**/cpuset.cpus ; do
        test "$cpscpus" == /sys/fs/cgroup/shield/cpuset.cpus && continue
        echo "$CPU_OTHERS" > $cpscpus
    done ; sleep 0.75
    echo root  > /sys/fs/cgroup/shield/cpuset.cpus.partition # exclusive
    test "root" == "$(cat /sys/fs/cgroup/shield/cpuset.cpus.partition)" || {
        echo /sys/fs/cgroup/shield/cpuset.cpus.partition:
        cat /sys/fs/cgroup/shield/cpuset.cpus.partition
        die "failed to setup cpuset.cpus.partition"
    }
}

reset_cpu_cgroupv1() {
    echo "skipping reset cpu isolation"
    # echo "reset cpu isolation"
    # cset shield --reset
}

isolate_cpu_cgroupv1() {
    echo "skipping isolate cpu for cgroup v1"
    # echo "isolate cpu for cgroup v1"
    # cset shield --cpu="$CPU_ISOLATED" --kthread=on
}

unset_system() {
    echo "unset system"
    echo 2 > /proc/sys/kernel/randomize_va_space
    for cpon in /sys/devices/system/cpu/cpu*/online ; do
        echo 1 > $cpon
    done
    for scg in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor ; do
        echo $INITIAL_SCALING_GOV > $scg || :
    done
    if [ -e /sys/devices/system/cpu/cpufreq/boost ]; then
        echo 1 > /sys/devices/system/cpu/cpufreq/boost
    fi
    echo 4 > /proc/sys/kernel/perf_event_paranoid
    if is_cgroup_v2; then
        reset_cpu_cgroupv2
    else
        reset_cpu_cgroupv1
    fi
}

set_system() {
    echo "system setup"
    echo 0 > /proc/sys/kernel/randomize_va_space
    for scg in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor ; do
        echo performance > $scg || :
    done
    for cpu in $CPU_SIBLINGS; do
        echo 0 > /sys/devices/system/cpu/cpu$cpu/online
    done
    if [ -e /sys/devices/system/cpu/cpufreq/boost ]; then
        echo 0 > /sys/devices/system/cpu/cpufreq/boost
    fi
    echo 0 > /proc/sys/kernel/perf_event_paranoid
    if is_cgroup_v2; then
        isolate_cpu_cgroupv2
    else
        isolate_cpu_cgroupv1
    fi
}

unset_ifaces() {
    echo "unset ifaces"
    # remove ifaces
    ip link set $IFACE1 down 2>/dev/null
    ip link set $IFACE2 down 2>/dev/null
    ip link delete $IFACE1 2>/dev/null
    ip link delete $IFACE2 2>/dev/null

    # remove net namespaces
    ip netns delete $NS1 2>/dev/null
    ip netns delete $NS2 2>/dev/null
}

set_ifaces() {
    echo "ifaces setup"
    # setup the net namespaces
    ip netns add $NS1 || die "failed to create $NS1 net namespace"
    ip netns add $NS2 || die "failed to create $NS2 net namespace"

    # create the veth ifaces
    ip link add $IFACE1 type veth peer name $IFACE2 || die "failed to create ifaces"

    # move ifaces to their namespace
    ip link set $IFACE1 netns $NS1 || die "failed to move iface1 to ns"
    ip link set $IFACE2 netns $NS2 || die "failed to move iface2 to ns"

    # configure interfaces in their namespaces
    ip netns exec $NS1 ip addr add $IP1/24 dev $IFACE1 || die "failed to setup iface1"
    ip netns exec $NS2 ip addr add $IP2/24 dev $IFACE2 || die "failed to setup iface2"

    # mount interfaces
    ip netns exec $NS1 ip link set $IFACE1 up || die "failed to up iface1"
    ip netns exec $NS2 ip link set $IFACE2 up || die "failed to up iface2"
}

check_dep() {
    if ! type $1 > /dev/null 2>&1; then
        die "$1 not available, please install it and retry again"
    fi
}

run_iperf_server() {
    # -s: server mode
    # -D: to daemonise
    # -1: to exit after one client bench
    taskset -c $CPU_SERVER \
         nice -20 \
         ip netns exec $NS1 \
         iperf3 -s -D || die "failed to run iperf server"
}

run_iperf_client() {
    OUTPUT_JSON_FILE="output.json"
    # -c <server ip>: client mode
    # -t N: for test len
    # -d: for dual
    # -o N: to omit the first N sec of bench on results
    # -Z: use zerocopy
    # --repeating-payload: do not use urandom for payloads
    # -J: json output
    ## don't use:
    # -P N: paralel bench on N threads
    # -u: for UDP
    taskset -c $CPU_CLIENT \
         nice -20 \
         ip netns exec $NS2 \
         iperf3 -c $IP1 -t 13 -O 3 -Z --repeating-payload -4 -J > "$OUTPUT_JSON_FILE" || die "failed to run iperf client"
    SENT=$(jq -r .end.sum_sent.bits_per_second "$OUTPUT_JSON_FILE")
    RECV=$(jq -r .end.sum_received.bits_per_second "$OUTPUT_JSON_FILE")
    # bits/s to Gb/s
    SENT=$(echo "scale=9; $SENT / 1000000000"|bc)
    RECV=$(echo "scale=9; $RECV / 1000000000"|bc)
    TOTAL=$(echo "$SENT + $RECV"|bc)
    echo "SUM SENT Gb/s: $SENT"
    echo "SUM RECV Gb/s: $RECV"
    echo "SUM TOTAL Gb/s: $TOTAL"
    rm -f "$OUTPUT_JSON_FILE" || :
}

run_sysprobe() {
    if [ ! -f $SYSPROBE_PATH ]; then
        die "system-probe not found"
    fi

    # enable CWS with all probes:
    export DD_RUNTIME_SECURITY_CONFIG_ENABLED=true
    export DD_EVENT_MONITORING_CONFIG_ENABLE_ALL_PROBES=true

    # disable unneeded features
    export DD_RUNTIME_SECURITY_CONFIG_ACTIVITY_DUMP_ENABLED=false
    export DD_RUNTIME_SECURITY_CONFIG_SECURITY_PROFILE_ENABLED=false
    export DD_RUNTIME_SECURITY_CONFIG_SBOM_ENABLED=false
    export DD_RUNTIME_SECURITY_CONFIG_HASH_RESOLVER_ENABLED=false

    # configure which network probes we should run (may be overrideed by config_all_probes??)
    export DD_RUNTIME_SECURITY_CONFIG_NETWORK_ENABLED=true
    export DD_RUNTIME_SECURITY_CONFIG_NETWORK_INGRESS_ENABLED=true
    export DD_RUNTIME_SECURITY_CONFIG_NETWORK_RAW_PACKET_ENABLED=true
    export DD_RUNTIME_SECURITY_CONFIG_NETWORK_FLOW_MONITOR_ENABLED=true
    export DD_RUNTIME_SECURITY_CONFIG_NETWORK_FLOW_MONITOR_SK_STORAGE=true

    # launch system-probe binary
    taskset -c $CPU_SYSPROBE \
            $SYSPROBE_PATH --config /tmp
}

usage() {
    echo "./bench [COMMAND]..."
    echo "  COMMANDS:"
    echo "    setup: setup the bench environment"
    echo "    clean: cleanup the bench environment"
    echo "    bench: launch iperf benchmark"
    echo "    sysprobe: start system-probe (will block until ^C)"
}

###
# MAIN SCRIPT STARTS HERE
###

# check dependencies
for util in $NEEDED_UTILS; do
    check_dep $util
done

# checking we are running as root
if (( EUID != 0 )); then
    echo "This script must be run as root"
    exit 1
fi

# check cgroup version
if ! is_cgroup_v2; then
    echo "cgroupv1 detected, cpu isolation though cgroupv2 won't be possible, please consider using isolcpu grub cmdline option instead"
fi


SETUP_FLAG="/tmp/.bench_setup_done"
# Loop through all arguments
for arg in "$@"; do
    case "$arg" in
        "setup")
            echo "setting up the bench environment"
            set_ifaces
            set_system
            touch "$SETUP_FLAG"
            ;;

        "clean")
            echo "unset the bench environment"
            rm -f "$SETUP_FLAG"
            cleanup
            ;;

        "bench")
            if [ ! -e "$SETUP_FLAG" ]; then
                echo "please setup the environmen before run the bench"
                usage
                exit 1
            fi
            sleep 1
            run_iperf_server
            run_iperf_client
            ;;

        "sysprobe")
            run_sysprobe
            ;;

        *)
            die "Unknown argument: $arg"
            ;;
    esac
done

exit 0
