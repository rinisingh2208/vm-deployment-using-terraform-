import argparse
from pyVmomi import vim
from pyVim.connect import SmartConnectNoSSL, Disconnect
import datetime
import sys

def get_rp_details(content, r_pool, minimum_required_cpu, minimum_required_memory):
    containerView = content.viewManager.CreateContainerView(content.rootFolder, [vim.ResourcePool], True)
    memory_check_status = 0
    cpu_check_status = 0
    available_memory =0
    available_cpu = 0
    try:
        for rp in containerView.view:
            if rp.name == r_pool:
                # print(rp.summary)
                # memory calculation (conversion from bytes to giga bytes)
                used_memory = ((rp.runtime.memory.reservationUsed / 1024) / 1024) / 1024
                available_memory = ((rp.runtime.memory.unreservedForPool / 1024) / 1024) / 1024
                rp_memory_capacity = ((rp.runtime.memory.maxUsage / 1024) / 1024) / 1024

                # cpu calculation (conversion from mhz to ghz)
                used_cpu = rp.runtime.cpu.reservationUsed / 1000
                available_cpu = rp.runtime.cpu.unreservedForPool / 1000
                rp_cpu_capacity = rp.runtime.cpu.maxUsage / 1000
        print(
            "\tavailable_memory = {} , minimum_required_memory = {} ".format(available_memory, minimum_required_memory))
        print("\tavailable_cpu = {} , minimum_required_cpu = {} ".format(available_cpu, minimum_required_cpu))
        if available_memory >= minimum_required_memory and available_cpu >= minimum_required_cpu:
            return True
        return False
    except Exception as error:
        print("Found error in resourcepool availablity check")
        print(error)
        sys.exit(1)
    finally:
        containerView.Destroy()


def find_object_by_name(folder, name):
    for child in folder.childEntity:
        if child.name == name:
            return child
    return None


def check_resources_esxi(user, password, host, esxi, vm_cpu, vm_memory, vm_disk, num_vms):
    # Connect to vSphere
    si = SmartConnectNoSSL(
        host=host,
        user=user,
        pwd=password,
        port=443)

    # Get the root folder
    content = si.RetrieveContent()
    root_folder = content.rootFolder
    perf_dict = {}

    # Get the vCenter instance UUID
    vsphere = si.content.about.instanceUuid

    # Get the performance manager and summary objects
    perfManager = content.perfManager
    summary = content.perfManager.perfCounter

    # Build the dictionary of performance counters
    perfList = summary
    for counter in perfList:
        counter_full = "{}.{}.{}".format(counter.groupInfo.key, counter.nameInfo.key, counter.rollupType)
        perf_dict[counter_full] = counter.key

        # Define the list of performance counter names to query
    counters_name = ['cpu.usage.average', 'mem.usage.average']

    # Define the start and end time for the performance query
    timenow = datetime.datetime.now()
    startTime = timenow - datetime.timedelta(minutes=30)
    endTime = timenow

    # Define the list to store the average values for each performance counter
    averagelist = []

    # Query the performance statistics for each performance counter
    for counter_name in counters_name:
        counterId = perf_dict[counter_name]
        metricId = vim.PerformanceManager.MetricId(counterId=counterId, instance="")
        search_index = content.searchIndex
        # Query the performance data for the specified metric
        host = search_index.FindByDnsName(dnsName=esxi, vmSearch=False)
        query = vim.PerformanceManager.QuerySpec(
            metricId=[metricId],
            startTime=startTime,
            endTime=endTime,
            maxSample=1,
            entity=host,
            intervalId=20
        )
        result = perfManager.QueryPerf(querySpec=[query])

        # Calculate the average value for the performance counter
        if result:
            value = result[0].value[0]
            averagelist.append(value)

    # Calculate the total CPU and memory resources required by the VMs
    total_cpu = int(vm_cpu) * int(num_vms)
    total_memory = int(vm_memory) * int(num_vms) / 1024

    # Check whether the available CPU and memory resources are enough
    cpu_usage_percent = averagelist[0].value[0] / 100.0
    memory_usage_percent = averagelist[1].value[0] / 100.0
    cpu_free_percent = 100.0 - cpu_usage_percent
    memory_free_percent = 100.0 - memory_usage_percent
    hosts = si.content.searchIndex.FindAllByIp(ip=esxi, vmSearch=False)
    hardware_info = hosts[0].hardware
    total_cpu_capacity = (hardware_info.cpuInfo.numCpuCores * hardware_info.cpuInfo.hz) / 1000000000
    free_value_cpu = (cpu_free_percent / 100) * total_cpu_capacity
    required_value_cpu = total_cpu

    free_value_memory = (memory_free_percent / 100) * hardware_info.memorySize / (1024 * 1024 * 1024)
    if required_value_cpu <= free_value_cpu and \
            total_memory <= free_value_memory:
        print("OK: There are enough resources for {num_vms} VMs with {vm_cpu} CPU, {vm_memory} Mib memory, and {vm_disk} GB disk.".format(num_vms=num_vms, vm_cpu=vm_cpu, vm_memory=vm_memory, vm_disk=vm_disk))
        return 0
    else:
        print("ERROR: There not are enough resources for {num_vms} VMs with {vm_cpu} CPU, {vm_memory} Mib memory, and {vm_disk} GB disk.".format(num_vms=num_vms, vm_cpu=vm_cpu, vm_memory=vm_memory, vm_disk=vm_disk))
        return 1

    # Disconnect from vSphere
    Disconnect(si)

def main_function(**kwargs):
    if not kwargs:
       parser = argparse.ArgumentParser()
       parser.add_argument("-user", "--user", help="vsphere user", required=True)
       parser.add_argument("-password", "--password", help="vsphere password", required=True)
       parser.add_argument("-host", "--host", help="vsphere host", required=True)
       parser.add_argument("-esxi", "--esxi", help="esxi host", required=True)
       parser.add_argument("-cpu", "--cpu", help="vm cpu", required=True)
       parser.add_argument("-mem", "--mem", help="vm memory",)
       parser.add_argument("-disk", "--disk", help="vm disk", required=True)
       parser.add_argument("-rp", "--rp", help="resource pool", required=True)
       parser.add_argument("-nums", "--nums", help="vm number", required=True)
       args = parser.parse_args()
       user = args.user
       password = args.password
       host = args.host
       esxi = args.esxi
       cpu = args.cpu
       mem = args.mem
       disk = args.disk
       resource_pool = args.rp
       vm_nums = args.nums
    else:
        user = kwargs.get("user")
        password=kwargs.get("password")
        host=kwargs.get("host")
        esxi=kwargs.get("esxi")
        cpu=kwargs.get("cpu")
        mem=kwargs.get("mem")
        disk=kwargs.get("disk") 
        resource_pool=kwargs.get("rp")
        vm_nums=kwargs.get("nums")

    esxi_resource_check=check_resources_esxi(user, password, host, esxi, cpu, mem, disk, vm_nums)
    si = SmartConnectNoSSL(
         host=host,
         user=user,
         pwd=password,
         port=443)

        # Get the root folder
    content = si.RetrieveContent()
    minimum_required_cpu = int(cpu) * int(vm_nums)
    minimum_required_memory = int(mem) * int(vm_nums) / 1024
    rp_check = get_rp_details(content, resource_pool, minimum_required_cpu, minimum_required_memory)
    if rp_check == True and esxi_resource_check == 0 :
       print("resourcepool and esxi have enough resources")
       return 0
    else:
        print("resourcepool and esxi don't have enough resources")
        return 1

if __name__ == '__main__':
    main_function()
