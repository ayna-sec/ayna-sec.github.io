#!/bin/bash
# This script will install all the necessary components for TheHive

GREEN=`echo -e "\033[32m"`
BLUE=`echo -e "\033[0;34m"`
NORMAL=`echo -e "\033[0m"`

echo "
┌─────────────────────────────────┐
│                                 │
│  _____ _       _____ _          │
│ |_   _| |_ ___|  |  |_|_ _ ___  │
│   | | |   | -_|     | | | | -_| │
│   |_| |_|_|___|__|__|_|\_/|___| │
│                                 │
└─────────────────────────────────┘
                                                         
"

# Dependencies installation
echo "$GREEN> INSTALLING DEPENDENCIES$NORMAL
"

sudo apt install wget gnupg apt-transport-https git ca-certificates ca-certificates-java curl software-properties-common python3-pip lsb-release

# Java installation
echo "
$GREEN> Java installation$NORMAL
"

wget -qO- https://apt.corretto.aws/corretto.key | sudo gpg --dearmor -o /usr/share/keyrings/corretto.gpg
echo "deb [signed-by=/usr/share/keyrings/corretto.gpg] https://apt.corretto.aws stable main" | sudo tee -a /etc/apt/sources.list.d/corretto.sources.list
sudo apt update
sudo apt install java-common java-11-amazon-corretto-jdk
echo JAVA_HOME="/usr/lib/jvm/java-11-amazon-corretto" | sudo tee -a /etc/environment
export JAVA_HOME="/usr/lib/jvm/java-11-amazon-corretto"
java -version

# Apache Cassandra installation
echo "
$GREEN> Apache Cassandra installation$NORMAL
"

wget -qO -  https://downloads.apache.org/cassandra/KEYS | sudo gpg --dearmor  -o /usr/share/keyrings/cassandra-archive.gpg
echo "deb [signed-by=/usr/share/keyrings/cassandra-archive.gpg] https://debian.cassandra.apache.org 40x main" |  sudo tee -a /etc/apt/sources.list.d/cassandra.sources.list 

sudo apt update
sudo apt install cassandra

echo "$GREEN[!] Data is stored in /var/lib/cassandra. Ensure appropiate permissions are set."
echo -e "[!] Don't forget to adjust the Cassandra configuration, before starting the service, in /etc/cassandra/cassandra.yaml.
Edit...
cluster_name
listen_address # address for nodes
rpc_address # address for clients
seed_provider
directories
$NORMAL
"

# Elasticsearch installation
echo "
$GREEN>Elasticsearch installation$NORMAL
"

wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch |  sudo gpg --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg
sudo apt-get install apt-transport-https
echo "deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] https://artifacts.elastic.co/packages/7.x/apt stable main" |  sudo tee /etc/apt/sources.list.d/elastic-7.x.list 
sudo apt update
sudo apt install elasticsearch


echo -e "$BLUE[!] Don't forget to adjust the Elasticsearch configuration, before starting the service, in /etc/elasticsearch/elasticsearch.yml
Edit...
cluster_name
http.host
transport.host
thread_pool.search.queue_size
path.logs
path.data
$NORMAL
"

# File storage set up
echo "
$GREEN> File storage set up$NORMAL
"

sudo mkdir -p /opt/thp/thehive/files
echo "$BLUE[!] Directory created in /opt/thp/thehive/file$NORMAL"
chown -R $(whoami):$($whoami) /opt/thp/thehive/files

# TheHive installation
echo "
$GREEN> TheHive installation$NORMAL
"
wget -O- https://raw.githubusercontent.com/StrangeBeeCorp/Security/main/PGP%20keys/packages.key | sudo gpg --dearmor -o /usr/share/keyrings/strangebee-archive-keyring.gpg
echo 'deb [arch=all signed-by=/usr/share/keyrings/strangebee-archive-keyring.gpg] https://deb.strangebee.com thehive-5.3 main' |sudo tee -a /etc/apt/sources.list.d/strangebee.list
sudo apt-get update
sudo apt-get install -y thehive

echo -e "$GREEN[!] Don't forget to adjust TheHive configuration in /etc/thehive/application.conf
[!] The secret key is automatically generated and stored in /etc/thehive/secret.conf
[!] Once all the components are configured, we can start the services...
Run:
$BLUEsudo systemctl start cassandra elasticsearch thehive
sudo systemctl enable cassandra elasticsearch thehive

$GREEN[!] You'll be able to access TheHive on http://YOUR_SERVER_ADDRESS:9000/
$NORMAL"
