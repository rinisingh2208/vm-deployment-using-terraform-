####################

# This script deploy master or worker vm on vsphere or standalone esxi for deployment type minimal , resilient or scale
# Fill config.yaml
# currently we assume templates are not deployed already , in later version those checks will be handled
####################
import subprocess
import sys
import time

from prettytable import PrettyTable
import yaml
from pyVmomi import vim
from pyVim import connect
from pyVim.connect import Disconnect
import ssl
import logging
import json
import jsonschema

logging.basicConfig(filename='vm_deployment.log', level=logging.DEBUG, format='%(asctime)s %(levelname)s:%(message)s')


def get_server_type(server_ip, username, password):
    try:
        # Connect to the VMware server
        sslContext = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
        sslContext.check_hostname = False
        sslContext.verify_mode = ssl.CERT_NONE
        si = connect.SmartConnect(host=server_ip, user=username, pwd=password, sslContext=sslContext)
        # Check if the server is ESXi or vSphere
        is_esxi = False
        is_vsphere = False
        content = si.content
        about_info = content.about
        if about_info.apiType == "HostAgent":
            is_esxi = True
        elif about_info.apiType == "VirtualCenter":
            is_vsphere = True

        # Disconnect from the VMware server
        Disconnect(si)

        # Return the server type
        if is_esxi:
            return "esxi"
        elif is_vsphere:
            return "vsphere"
        else:
            raise ValueError("Unknown server type")
    except vim.fault.InvalidLogin as e:
        logging.error("Failed to connect to the VMware server: Invalid username or password")
        # You can also choose to raise the exception if you want to handle it further up the call stack
        # raise e
    except Exception as e:
        logging.error("An error occurred while connecting to the VMware server:", str(e))
        # You can also choose to raise the exception if you want to handle it further up the call stack


def get_vm_template_id(template_name, server_ip, username, password):
    """
    Searches for a template by name and returns its ID.
    """
    # Connect to the VMware server
    sslContext = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    sslContext.check_hostname = False
    sslContext.verify_mode = ssl.CERT_NONE
    si = connect.SmartConnect(host=server_ip, user=username, pwd=password, sslContext=sslContext)
    # Check if the server is ESXi or vSphere
    is_esxi = False
    is_vsphere = False
    content = si.content
    obj_view = content.viewManager.CreateContainerView(content.rootFolder, [vim.VirtualMachine], True)
    vm_list = obj_view.view
    obj_view.Destroy()
    for vm in vm_list:
        if vm.name == template_name:
            return vm.config.instanceUuid
    return None


def create_setup(vsphere_user, vsphere_password, vsphere_server, esxi_host, virtual_machine_domain, server_type,
                 vsphere_port_group_name,
                 vmware_template_name, template_folder_source, template_folder_destination, vsphere_datacenter,
                 vsphere_datastore, resource_pools_f, single_rp,
                 setup_count, vm_name_prefix, ip_address_f, vm_cpu, vm_memory, vm_disk_size, template_cpu,
                 template_memory, template_disk_size, tfstate_file_path, workspace_name, zone):
    # Search for the template by name and retrieve its ID
    template_id = get_vm_template_id(vmware_template_name, vsphere_server, vsphere_user, vsphere_password)
    if not template_id:
        print("Error: could not find template with name {vmware_template_name}".format(
            vmware_template_name=vmware_template_name))
        terraform_config = '''
            provider "vsphere" {{
              user= "{user}"
              password = "{password}"
              vsphere_server = "{server}"
              allow_unverified_ssl = true
            }}
            data "vsphere_datacenter" "dc" {{
             name = "{datacenter}"
            }}
            locals {{
             setup_count = {setup_count}
            }}
            data "vsphere_datastore" "ds" {{
             name = "{datastore}"
             datacenter_id = data.vsphere_datacenter.dc.id
            }}
            variable "resource_pools" {{
              type = list(string)
              default = {resource_pools_f}
            }}
            variable "ip_addresses" {{
              type    = list(string)
              default = {ip_address_f}
            }}
            variable "vm_name_prefix" {{
              type    = list(string)
              default = {vm_name_prefix}
            }}
            variable "vm_cpu" {{
              type    = list(string)
              default = {vm_cpu}
            }}
            variable "vm_memory" {{
              type    = list(string)
              default = {vm_memory}
            }}
            variable "vm_disk_size" {{
              type    = list(string)
              default = {vm_disk_size}
            }}
            data "vsphere_network" "network" {{
              name          = "{port_group_name}"
              datacenter_id = data.vsphere_datacenter.dc.id
            }}
            data "vsphere_resource_pool" "pool" {{
              for_each = toset(var.resource_pools)
              name     = each.value
              datacenter_id = data.vsphere_datacenter.dc.id
            }}
            data "vsphere_resource_pool" "pool1" {{
              name = "{single_rp}"
              datacenter_id = data.vsphere_datacenter.dc.id
            }}
            data "vsphere_host" "host" {{
              name          = "{host}"
              datacenter_id = data.vsphere_datacenter.dc.id
            }}
            data "vsphere_ovf_vm_template" "ovfLocal" {{
              name              ="{vmware_template_name}"
              disk_provisioning = "thin"
              resource_pool_id = data.vsphere_resource_pool.pool1.id
              datastore_id      = data.vsphere_datastore.ds.id
              host_system_id    = data.vsphere_host.host.id
              local_ovf_path    = "{template_folder_source}"
              folder = "{template_folder_destination}"
              enable_hidden_properties = true
              ovf_network_map = {{
                "VM Network" : data.vsphere_network.network.id
              }}
            }}
            resource "vsphere_virtual_machine" "myvm_template" {{
              name =  "{vmware_template_name}"
              guest_id = data.vsphere_ovf_vm_template.ovfLocal.guest_id
              datastore_id     = data.vsphere_datastore.ds.id
              resource_pool_id = data.vsphere_resource_pool.pool1.id
              host_system_id    = data.vsphere_host.host.id
              datacenter_id = data.vsphere_datacenter.dc.id
              num_cpus = {template_cpu}
              memory   = {template_memory}
              scsi_type =  data.vsphere_ovf_vm_template.ovfLocal.scsi_type
              nested_hv_enabled    = data.vsphere_ovf_vm_template.ovfLocal.nested_hv_enabled
              network_interface {{
                # Configuring the IP address of the network interface
                network_id          = data.vsphere_network.network.id
              }}
              disk {{
                label = "disk0"
                eagerly_scrub    = false
                thin_provisioned = true
                unit_number      = 0

                size  = {template_disk_size}
              }}
              ovf_deploy {{

                allow_unverified_ssl_cert = true
                local_ovf_path           = data.vsphere_ovf_vm_template.ovfLocal.local_ovf_path
                disk_provisioning         = data.vsphere_ovf_vm_template.ovfLocal.disk_provisioning
                ovf_network_map           = data.vsphere_ovf_vm_template.ovfLocal.ovf_network_map
              }}
             wait_for_guest_net_timeout = 15
             vapp {{
               properties = {{
               }}
             }}
            }}
            resource "vsphere_virtual_machine" "myvm" {{
              count=local.setup_count
              name = element(var.vm_name_prefix,count.index)
              resource_pool_id = data.vsphere_resource_pool.pool[var.resource_pools[count.index % length(var.resource_pools)]].id
              guest_id = resource.vsphere_virtual_machine.myvm_template.guest_id
              datastore_id     = data.vsphere_datastore.ds.id
              scsi_type =  resource.vsphere_virtual_machine.myvm_template.scsi_type
              num_cpus = element(var.vm_cpu,count.index)
              memory   = element(var.vm_memory,count.index)
              network_interface {{
                # Configuring the IP address of the network interface
                network_id          = data.vsphere_network.network.id
              }}
              disk {{
                label = "disk0"
                eagerly_scrub    = false
                thin_provisioned = true
                unit_number      = 0

                size  = element(var.vm_disk_size,count.index)
              }}
              clone {{
                template_uuid = resource.vsphere_virtual_machine.myvm_template.id

                customize {{
                  linux_options {{
                    domain = "{virtual_machine_domain}"
                    host_name = element(var.vm_name_prefix,count.index)
                  }}
                  network_interface {{
                    ipv4_address = element(var.ip_addresses,count.index)
                    ipv4_netmask = {vm_ipv4_subnet_mask}
                  }}
                  ipv4_gateway = "{vm_ipv4_gateway}"
                  dns_server_list = {dns_server_list}

                }}
              }}

            }}
            terraform {{
              backend "local" {{
                path = "{tfstate_file_path}/{workspace_name}/{zone}/terraform.tfstate"
                workspace_dir="{tfstate_file_path}/{workspace_name}"

              }}
            }}

        '''.format(resource_pools_f=resource_pools_f, vm_ipv4_subnet_mask=vm_ipv4_subnet_mask,
                   vm_ipv4_gateway=vm_ipv4_gateway, dns_server_list=dns_server_list,
                   tfstate_file_path=tfstate_file_path, workspace_name=workspace_name, zone=zone,
                   virtual_machine_domain=virtual_machine_domain, template_disk_size=template_disk_size,
                   template_memory=template_memory, template_cpu=template_cpu,
                   template_folder_source=template_folder_source,
                   template_folder_destination=template_folder_destination, user=vsphere_user,
                   password=vsphere_password, server=vsphere_server, datacenter=vsphere_datacenter,
                   datastore=vsphere_datastore, ip_address_f=ip_address_f, vm_name_prefix=vm_name_prefix, vm_cpu=vm_cpu,
                   vm_memory=vm_memory, vm_disk_size=vm_disk_size, port_group_name=vsphere_port_group_name,
                   single_rp=single_rp, host=esxi_host, setup_count=setup_count,
                   vmware_template_name=vmware_template_name)

    else:
        print(
            "Template already exist as " + vmware_template_name + " on " + vsphere_password + "over esxi " + esxi_host+" ,so we are continuing to create vm using it")
        time.sleep(60)
        terraform_config = '''
           provider "vsphere" {{
             user= "{user}"
             password = "{password}"
             vsphere_server = "{server}"
             allow_unverified_ssl = true
           }}
           data "vsphere_datacenter" "dc" {{
            name = "{datacenter}"
           }}
           locals {{
            setup_count = {setup_count}
           }}
           data "vsphere_datastore" "ds" {{
             name = "{datastore}"
             datacenter_id = data.vsphere_datacenter.dc.id
            }}
            variable "resource_pools" {{
              type = list(string)
              default = {resource_pools_f}
            }}
            variable "ip_addresses" {{
              type    = list(string)
              default = {ip_address_f}
            }}
            variable "vm_name_prefix" {{
              type    = list(string)
              default = {vm_name_prefix}
            }}
            variable "vm_cpu" {{
              type    = list(string)
              default = {vm_cpu}
            }}
            variable "vm_memory" {{
              type    = list(string)
              default = {vm_memory}
            }}
            variable "vm_disk_size" {{
              type    = list(string)
              default = {vm_disk_size}
            }}
            data "vsphere_virtual_machine" "template" {{
              name  = "{vmware_template_name}"
              datacenter_id = data.vsphere_datacenter.dc.id
            }}
            data "vsphere_network" "network" {{
              name          = "{port_group_name}"
              datacenter_id = data.vsphere_datacenter.dc.id
            }}
            data "vsphere_resource_pool" "pool" {{
              for_each = toset(var.resource_pools)
              name     = each.value
              datacenter_id = data.vsphere_datacenter.dc.id
            }}
            data "vsphere_resource_pool" "pool1" {{
              name = "{single_rp}"
              datacenter_id = data.vsphere_datacenter.dc.id
            }}
            resource "vsphere_virtual_machine" "myvm" {{
              count=local.setup_count
              name = element(var.vm_name_prefix,count.index)
              resource_pool_id = data.vsphere_resource_pool.pool[var.resource_pools[count.index % length(var.resource_pools)]].id
              guest_id = data.vsphere_virtual_machine.template.guest_id
              scsi_type =  data.vsphere_virtual_machine.template.scsi_type
              datastore_id     = data.vsphere_datastore.ds.id
              num_cpus = element(var.vm_cpu,count.index)
              memory   = element(var.vm_memory,count.index)
              network_interface {{
                # Configuring the IP address of the network interface
                network_id          = data.vsphere_network.network.id
              }}
              disk {{
                label = "disk0"
                eagerly_scrub    = false
                thin_provisioned = true
                unit_number      = 0

                size  = element(var.vm_disk_size,count.index)
              }}
              clone {{
                template_uuid = data.vsphere_virtual_machine.template.id

                customize {{
                  linux_options {{
                    domain = "{virtual_machine_domain}"
                    host_name = element(var.vm_name_prefix,count.index)
                  }}
                  network_interface {{
                    ipv4_address = element(var.ip_addresses,count.index)
                    ipv4_netmask = {vm_ipv4_subnet_mask}
                  }}
                  ipv4_gateway = "{vm_ipv4_gateway}"
                  dns_server_list = {dns_server_list}

                }}
              }}

            }}
            terraform {{
              backend "local" {{
                path = "{tfstate_file_path}/{workspace_name}/{zone}/terraform.tfstate"
                workspace_dir="{tfstate_file_path}/{workspace_name}"

              }}
            }}
           '''.format(resource_pools_f=resource_pools_f, vm_ipv4_subnet_mask=vm_ipv4_subnet_mask,
                      vm_ipv4_gateway=vm_ipv4_gateway, dns_server_list=dns_server_list,
                      tfstate_file_path=tfstate_file_path, workspace_name=workspace_name, zone=zone,
                      virtual_machine_domain=virtual_machine_domain, template_disk_size=template_disk_size,
                      template_memory=template_memory, template_cpu=template_cpu,
                      template_folder_source=template_folder_source,
                      template_folder_destination=template_folder_destination, user=vsphere_user,
                      password=vsphere_password, server=vsphere_server, datacenter=vsphere_datacenter,
                      datastore=vsphere_datastore, ip_address_f=ip_address_f, vm_name_prefix=vm_name_prefix,
                      vm_cpu=vm_cpu,
                      vm_memory=vm_memory, vm_disk_size=vm_disk_size, port_group_name=vsphere_port_group_name,
                      single_rp=single_rp, host=esxi_host, setup_count=setup_count,
                      vmware_template_name=vmware_template_name)

    subprocess.call(['mkdir', '-p', tfstate_file_path + workspace_name + "/" + zone])
    if server_type == "vsphere" or server_type == "esxi":
        try:
            # Define the Terraform configuration in main.tf

            # subprocess.call(f'sh -c "cd {tfstate_file_path}/{workspace_name}/{zone}"', shell=True)
            with open(tfstate_file_path + "/" + workspace_name + "/" + zone + "/" + 'main.tf', 'w') as f:
                f.write(terraform_config)
            with open('main.tf', 'w') as f:
                f.write(terraform_config)

            # Initialize Terraform in the working directory
            # subprocess.call(['terraform', 'init'])

            # Deploy the virtual machine using Terraform
            # subprocess.call(['terraform', 'plan'])
            # subprocess.call(['terraform', 'apply', '-auto-approve'])
            try:
                # Initialize Terraform in the working directory
                # subprocess.call(f'sh -c "cd {tfstate_file_path}/{workspace_name}/{zone}"', shell=True)
                subprocess.call(['terraform', 'init', '-reconfigure', '-input=false'])
                subprocess.call(['terraform', 'workspace', 'new', zone])
                subprocess.call(['terraform', 'workspace', 'select', zone])

                subprocess.call(['terraform', 'apply', '-auto-approve'])
                # subprocess.call(['cp', workspace_name+"/"+zone+"/terraform.tfstate", tfstate_file_path+"/"+workspace_name+"/"+zone])
                # ubprocess.call(['terraform', 'init', '-reconfigure', '-input=false'])
                # Deploy...
            except Exception as e:
                print("An error occurred: {e}")

                # Determine the cause of the error
                if "Error: Failed to apply" in str(e):
                    resource_name = e.output.decode().splitlines()[-1].split()[-1].strip('"')
                    subprocess.call(['terraform', 'init', '-reconfigure', '-input=false'])
                    subprocess.call(['terraform', 'workspace', 'new', zone])
                    subprocess.call(['terraform', 'workspace', 'select', zone])
                    # Start deployment from the point of failure
                    subprocess.call(['terraform', 'plan'])
                    subprocess.call(['terraform', 'apply', '-target=' + resource_name, '-auto-approve'])
                else:
                    # Start deployment from the beginning
                    subprocess.call(['terraform', 'init', '-reconfigure', '-input=false'])
                    subprocess.call(['terraform', 'workspace', 'new', zone])
                    subprocess.call(['terraform', 'workspace', 'select', zone])
                    subprocess.call(['terraform', 'plan'])
                    subprocess.call(['terraform', 'apply', '-auto-approve'])

        except (ValueError, subprocess.CalledProcessError) as e:
            logging.error("An error occurred: {str(e)}")


def check_minimum_count(nt, dt):
    if dt == "minimal":
        if nt == "master":
            minimum_count = 3
        if nt == "worker":
            minimum_count = 1
    elif dt == "resilient":
        if nt == "master":
            minimum_count = 3
        if nt == "worker":
            minimum_count = 9
    return minimum_count


if __name__ == '__main__':
    with open('schema.yaml', 'r') as f:
        schema = yaml.safe_load(f)
        # schema = jsonschema.validate(schema)

    # Load the updated YAML file
    with open('config.yaml', 'r') as f:
        yaml_vars = yaml.safe_load(f)
    # Validate the updated YAML file against the schema
    jsonschema.validate(schema, yaml_vars)
    deployment_type = yaml_vars["deployment_type"]
    num_zones = len(yaml_vars["zones"])
    # checking in zone count satisfy for each deployment type
    if deployment_type == "minimal":
        if num_zones == 1:
            pass
        else:
            print("For minimal setup only one zone need to be defined")
            sys.exit(1)
    elif deployment_type == "resilient":
        if num_zones != 2 and num_zones != 3:
            print("For resilient setup only minimum of 2 zones or maximum of 3 zones need to be defined")
            sys.exit(1)
        else:
            pass
    elif deployment_type == "scale":
        if num_zones == 3:
            pass
        else:
            print("For scale setup 3 zones need to be defined")
            sys.exit(1)
    else:
        print("Provide right deployment_type under the same section in config.yaml among minimal, resilient or scale")
        sys.exit(1)

    # create a new PrettyTable object with column names
    table = PrettyTable(
        ["Zone-Name", "vSphere Server", "ESXi Host", "Datacenter", "Datastore", "Resource Pools", "VMs", "CPU",
         "Memory", "Disk"])

    # for each node type check if minimum node count value meets
    masters = []
    workers = []
    for zone in yaml_vars["zones"]:
        vm_names = [vm['name'] for vm in zone["vms"]]
        for vm_name in vm_names:
            if "master" in vm_name:
                masters.append(vm_name)
            elif "worker" in vm_name:
                workers.append(vm_name)
    min_count_master = check_minimum_count("master", deployment_type)
    min_count_worker = check_minimum_count("worker", deployment_type)
    if (len(masters) >= min_count_master and len(workers) >= min_count_worker):
        pass
    else:
        print(
            "For deployment type " + deployment_type + " and node type master and worker minimum count should be " + str(
                min_count_master) + " and " + str(min_count_worker) + " respectively.")
        exit(1)
    # reading vsphere related info
    vsphere_user = yaml_vars['vsphere']['user']
    vsphere_password = yaml_vars['vsphere']['password']
    vsphere_port_group_name = yaml_vars['vsphere']['port_group_name']
    vmware_template_name = yaml_vars['vsphere']['template']['name']
    virtual_machine_domain = yaml_vars['vsphere']['domain']
    tfstate_file_path = yaml_vars['vsphere']['tfstate']['tfstate_file_path']
    workspace_name = yaml_vars['vsphere']['tfstate']['workspace_name']
    template_folder_source = yaml_vars['vsphere']['template']['source']
    template_folder_destination = yaml_vars['vsphere']['template']['destination']
    template_cpu = yaml_vars['vsphere']['template']['cpu_nums']
    template_memory = yaml_vars['vsphere']['template']['memory_mib']
    template_disk_size = yaml_vars['vsphere']['template']['disk_size_gib']

    for zone in yaml_vars["zones"]:
        # get the zone details
        name = zone["name"]
        vsphere_server = zone["vsphere_server"]
        esxi_host = zone["esxi_host"]
        datacenter = zone["datacenter"]
        datastore = zone["datastore"]
        server_type = get_server_type(vsphere_server, vsphere_user, vsphere_password)
        resource_pools_str = ", ".join(zone["resource_pools"])
        ip_addresses = [vm['ipv4_address'] for vm in zone["vms"]]
        vms = "\n".join(
            ["{vm_name} ({vm_ip_address})".format(vm_name=vm['name'], vm_ip_address=vm['ipv4_address']) for vm in
             zone["vms"]])
        vm_names = [vm['name'] for vm in zone["vms"]]
        vm_names = json.dumps(vm_names)
        resource_pools = []
        for rp in zone["resource_pools"]:
            resource_pools.append(rp)
        resource_pools_f = json.dumps(resource_pools)
        single_rp = resource_pools[0]

        # adding vm related specification in output table
        cpu = []
        memory = []
        disk = []

        master_count = 0
        worker_count = 0
        for vm in zone['vms']:
            if 'master' in vm['name']:
                vm_spec = yaml_vars['vm_specifications']['master']
                cpu.append(vm_spec['cpu_nums'])
                memory.append(vm_spec['memory_mib'])
                disk.append(vm_spec["disk_size_gib"])
                master_count += 1
            elif 'worker' in vm['name']:
                vm_spec = yaml_vars['vm_specifications']['worker']
                cpu.append(vm_spec['cpu_nums'])
                memory.append(vm_spec['memory_mib'])
                disk.append(vm_spec["disk_size_gib"])
                worker_count += 1
            cpu1 = "\n".join([str(x) for x in cpu])
            memory1 = "\n".join([str(x) for x in memory])
            disk1 = "\n".join([str(x) for x in disk])

        print("\n Checking resources for master/s node/s for zone " + name + " \n")
        import check_resources_vsphere as check_vsphere

        for resource_pool in resource_pools:
            ret_val = check_vsphere.main_function(user=vsphere_user, password=vsphere_password,
                                                  host=vsphere_server,
                                                  esxi=esxi_host,
                                                  cpu=yaml_vars['vm_specifications']['master']['cpu_nums'],
                                                  mem=yaml_vars['vm_specifications']['master']['memory_mib'],
                                                  disk=yaml_vars['vm_specifications']['master']['disk_size_gib'],
                                                  rp=resource_pool, nums=master_count)
            if ret_val == 0:
                pass
            else:
                sys.exit(1)
        print("\n Checking resources for worker/s node/s " + name + " \n")
        for resource_pool in resource_pools:
            ret_val = check_vsphere.main_function(user=vsphere_user, password=vsphere_password,
                                                  host=vsphere_server,
                                                  esxi=esxi_host,
                                                  cpu=yaml_vars['vm_specifications']['worker']['cpu_nums'],
                                                  mem=yaml_vars['vm_specifications']['worker']['memory_mib'],
                                                  disk=yaml_vars['vm_specifications']['worker']['disk_size_gib'],
                                                  rp=resource_pool, nums=worker_count)
            if ret_val == 0:
                pass
            else:
                sys.exit(1)

        # reading vm specs with network specs
        ip_address_f = json.dumps(ip_addresses)
        vm_ipv4_gateway = yaml_vars['network']["ipv4_gateway"]
        vm_ipv4_subnet_mask = yaml_vars['network']["ipv4_subnet_mask"]
        dns_server = yaml_vars['network']['dns_server_list']
        dns_server_list = dns_server.split(",")
        dns_server_list = json.dumps(dns_server_list)

        print("\n Creating " + str(len(masters)) + " vm for node type master \n")

        print("\n Creating " + str(len(workers)) + " vm for node type worker \n")
        # add a new row to the table
        table.add_row(
            [name, vsphere_server, esxi_host, datacenter, datastore, resource_pools_str, vms, cpu1, memory1, disk1])

        create_setup(vsphere_user, vsphere_password, vsphere_server, esxi_host, virtual_machine_domain, server_type,
                     vsphere_port_group_name, vmware_template_name, template_folder_source, template_folder_destination,
                     datacenter, datastore, resource_pools_f, single_rp, len(zone['vms']), vm_names,
                     ip_address_f, cpu, memory, disk, template_cpu, template_memory, template_disk_size,
                     tfstate_file_path, workspace_name, zone['name'])

    # Print table
    print("\n")
    print(table)
    print("\n \t Deployed " + deployment_type + " type cluster with above configuration \n")
