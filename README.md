# Ansible Tetration Sensors
This application helps to quickly deploy Tetration Agents for all kinds of OS (Ubuntu, CentOS, Windows) automatically. 

## Table of contents
* [Requirements](#Requirements)
* [Installation](#Installation)
* [Screenshots](#screenshots)
* [How to Use](#UserGuide)
* [Feedback and Author](#Feedback)

## Requirements

* Ansible should be pre-installed on the control machine
* Install required python libraries to control Windows Machine.
	```
	pip install pywinrm
	export OBJC_DISABLE_INITIALIZE_FORK_SAFETY=YES
	```

* Install winrm in windows hosts (need to install winrm in the windows servers, using powershell to install this ps script: https://raw.githubusercontent.com/ansible/ansible/devel/examples/scripts/ConfigureRemotingForAnsible.ps1) . 

* Make sure ssh (username and password) and keys are available for Linux and Ubuntu servers.

## Installation

* From sources

Download the sources from [Github](https://github.com/leeahnduk/ansible-tetration-sensors-all.git), extract and execute the following commands

```
$ git clone https://github.com/leeahnduk/ansible-tetration-sensors-all.git

```
* Navigate to the main repository directory
* Add your hosts to inventory file
* Download sensors and put it into folder and change folder location in group_vars/all
* Update group_vars/all with following varibles
``` 
linux_sensor_file: /Sensors/tet-sensor.rpm
win_sensor_file: /Sensors/tet-sensor.zip
activation_key: your activation key

linux_sensor_shell_script: /Sensors/tet-linux.sh
win_sensor_ps_script: /Sensors/tet_sensor.ps1
```
* Also add username and password for all the hosts i.e. inventory/hosts
```
[centos]
192.168.33.135
192.168.33.136
192.168.33.137
[centos:vars]
ansible_user=ansible
#ansible_password=tet123$$!
#ansible_sudo_pass=tet123$$!

[ubuntu]
192.168.36.29
[ubuntu:vars]
ansible_port=22 
ansible_user=ubuntu

[win]
192.168.32.103
[win:vars]
ansible_user=administrator
ansible_password=C1scoUC$
ansible_connection=winrm
ansible_winrm_transport=ntlm
ansible_winrm_server_cert_validation=ignore
validate_certs=false
```

## Screenshots
![Run screenshot](https://github.com/leeahnduk/ansible-tetration-sensors-all/blob/master/Ansible.jpg)
![Result screenshot](https://github.com/leeahnduk/ansible-tetration-sensors-all/blob/master/clean.jpg)
![Tetration screenshot](https://github.com/leeahnduk/ansible-tetration-sensors-all/blob/master/result.jpg)


## UserGuide

* Run the following command to install Tetration Sensor for specific OS:
```
	ansible-playbook -i hosts/hosts tet_install_win.yaml (using ps script)

	ansible-playbook -i hosts/hosts tet_install_win_msi.yaml (using msi)

	ansible-playbook -i hosts/hosts tet_install_ubuntu.yaml

	ansible-playbook -i hosts/hosts tet_install_centos.yaml (using sh script)

	ansible-playbook -i hosts/hosts tet_install_centos_rpm.yaml (using rpm)
```

* Run the following command to install Tetration Sensors for all OS in hosts file:
```
	ansible-playbook -i hosts/hosts tet_install_new.yaml (using scripts for windows and centos)

	ansible-playbook -i hosts/hosts tet_install_oldway.yaml (using rpm and msi)
```

* Run the following command to remove Tetration Sensor for specific OS: 
```
	ansible-playbook -i hosts/hosts clean_OS.yaml
```

## Feedback
Any feedback can send to me: Le Anh Duc (leeahnduk@yahoo.com or anhdle@cisco.com)
