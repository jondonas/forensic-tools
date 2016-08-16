Access Key ID: [Access Key ID]
Secret Access Key: [Secret Access Key]

Make sure to configure proper security group access

sudo add-apt-repository ppa:saltstack/salt
sudo apt-get update
sudo apt-get install python-software-properties salt-master salt-cloud
[on local machine] scp -i ~/master.pem ~/master.pem ubuntu@ec2-54-172-110-211.compute-1.amazonaws.com:~/
mv master.pem /etc/salt/

sudo vim /etc/salt/cloud.providers.d/ec2-us-east-1.conf
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

sudo vim /etc/salt/cloud.profiles.d/ec2-us-east-1.conf
```
ec2_east_nano_prod:
  provider: ec2-us-east-1-public
  image: ami-2d39803a
  size: t2.nano
  ssh_username: ubuntu
  tag: {'Environment': 'production'}
  sync_after_install: grains
```

sudo salt-cloud -p ec2_east_nano_prod saltcloud_test

cloud map:
sudo vim /etc/salt/cloud.maps.d/cmap.ec2
```
ec2_east_nano_prod:
  - salt_test1
  - salt_test2
  - salt_test3
```

sudo salt-cloud -m /etc/salt/cloud.maps.d/cmap.ec2 -P



On dnmap server:
sudo apt-get install python-openssl python-twisted
sudo wget http://downloads.sourceforge.net/project/dnmap/dnmap_v0.6.tgz -P /opt
sudo tar -xvzf dnmap_v0.6.tgz

sudo mkdir /srv/salt
sudo vim /srv/salt/dnmap.sls
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
sudo vim vim /srv/salt/top.sls
```
base:
  '*':
    - dnmap
```

sudo salt '*' state.highstate


sudo vim /opt/dnmap_v0.6/commands.txt
```
nmap -sV 54.152.175.250
```

in /opt/dnmap_v0.6/
sudo ./dnmap_server.py -f commands.txt


sudo salt '*' cmd.run '/opt/dnmap_v0.6/dnmap_client.py -s 54.172.110.211 -a minion-$(ifconfig eth0 | grep "inet addr" | cut -d: -f2 | cut -d" " -f1)'



sudo salt-cloud -m /etc/salt/cloud.maps.d/cmap.ec2 -a reboot
