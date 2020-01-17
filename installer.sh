# Interaller script should be the only thing that is needed to be ran on most 
# sytems. Only tested on ubuntu 16.04 LTS
# Install path needs to be in the /opt/C2DEF/

# Step one setup the basics
apt-get update
apt-get -y install python
apt-get -y install python-pip
apt-get -y iptables 
apt-get -y install tcpdump

#Step two install the.
pip install -r /opt/C2DEF/requirements.txt

#copy to bin
cp /opt/C2DEF/server/chameleon /bin/
chmod +x /bin/chameleon
chmod +x /opt/C2DEF/server/training/samplebyid

#start it up
chameleon --start
chameleon --stop

echo "Setup completed...."
