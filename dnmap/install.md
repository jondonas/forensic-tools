##Installation

Make sure to configure proper security group access for AWS instances. Eg, allow all inbound and outbound.

###Install salt on master
```
sudo add-apt-repository ppa:saltstack/salt
sudo apt-get update
sudo apt-get install python-software-properties salt-master salt-cloud
scp -i ~/master.pem ~/master.pem ubuntu@[master-ip]:~/ (on local machine)
mv master.pem /etc/salt/
```

###Configure providers (aws in this case)
Create and configure: /etc/salt/cloud.providers.d/ec2-us-east-1.conf
```
ec2-us-east-1-public:
  minion:
    master: 54.172.110.211
  id: [Access Key ID]
  key: [Secret Access Key]
  private_key: /etc/salt/master.pem
  keyname: Master
  ssh_interface: public_ips
  securitygroup: default
  location: us-east-1
  availability_zone: us-east-1a
  provider: ec2
  del_root_vol_on_destroy: True
  del_all_vols_on_destroy: True
  rename_on_destroy: True
```

###Configure profile
Create and configure: /etc/salt/cloud.profiles.d/ec2-us-east-1.conf
```
ec2_east_nano_prod:
  provider: ec2-us-east-1-public
  image: ami-2d39803a
  size: t2.nano
  ssh_username: ubuntu
  tag: {'Environment': 'production'}
  sync_after_install: grains
```
###Spin up a single instance for a test
```
sudo salt-cloud -p ec2_east_nano_prod saltcloud_test
```

###Create a cloud map
Create and configure: /etc/salt/cloud.maps.d/cmap.ec2
```
ec2_east_nano_prod:
  - salt_test1
  - salt_test2
  - salt_test3
```
###Spin up instances with a cloud map
```
sudo salt-cloud -m /etc/salt/cloud.maps.d/cmap.ec2 -P
```

###Shutdown/restart/etc minions
```
sudo salt-cloud -m /etc/salt/cloud.maps.d/cmap.ec2 -a [reboot/stop/destroy]
```

###Setup dnmap on master
```
sudo apt-get install python-openssl python-twisted
sudo wget http://downloads.sourceforge.net/project/dnmap/dnmap_v0.6.tgz -P /opt
sudo tar -xvzf dnmap_v0.6.tgz
```

###Create a salt state to install dnmap on minions
Create and configure: /srv/salt/dnmap.sls
```
nmap:
  pkg:
    - installed
python-openssl:
  pkg:
    - installed
python-twisted:
  pkg:
    - installed
sudo wget http://downloads.sourceforge.net/project/dnmap/dnmap_v0.6.tgz -P /opt:
  cmd.run
sudo tar -xvzf /opt/dnmap_v0.6.tgz -C /opt:
  cmd.run
sudo rm /opt/dnmap_v0.6.tgz:
  cmd.run
```
Create and configure: /srv/salt/top.sls
```
base:
  '*':
    - dnmap
```

###Apply salt states to minions
```
sudo salt '*' state.highstate
```

###Create a commands file for dnmap. Alternatively, use command-maker.py file to create file
Create and configure: /opt/dnmap_v0.6/commands.txt
```
nmap -sV [ip]
```

###Run dnmap on master
```
sudo ./dnmap_server.py -f commands.txt
```

###Connect minions (run on master)
```
sudo salt '*' cmd.run '/opt/dnmap_v0.6/dnmap_client.py -s 54.172.110.211 -a minion-$(ifconfig eth0 | grep "inet addr" | cut -d: -f2 | cut -d" " -f1)'
```
