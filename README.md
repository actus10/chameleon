# A10 Networks Chameleon Community Security Research Framework (CCSRF)
### Adaptive and Deceptive Threat Intelligence HoneyPot
__author__: Mike Thompson,
__status__: alpha,
__version__:0.5,
__date__: Sat, 4 Nov 2017

__license__: A10 Networks Security Community License

[LAB WIKI](https://github.com/a10networks/C2DEF/wiki)

Forward
-------
A10 SERT reconized that a new breed of honeypot is required to address the new wavy of malware targeting IoT technologies.
I hope that contributions back to this project will enable a better community version.
More imporantly, we need a highly portable approach that required less human resources and higher confidence intelligence.
The A10's SERT team wanted a creative way to not only detect Bot-net activity, but also a means to join a BotNet without having to deal with the pain staking task of tracking down hardware and software for the latest CVE.

Thus, Chameleon was born.

The community version of our project is aimed at security researchers who needs a tool that can leverage machine learning and rapid development. I personally view Chameleon CSRF as a framework as much as I view it as a platform. It takes the best of python, machine learning and other concepts and provides sensor that can be deployed in many ways.
Initially, A10 SERT is restricting the first couple of releases in order resolve and passive or active figer printing issues. Right now we are working on the notion of personas in order to mimic the behaviro of different applications, Devices and Operating Systems.
It is the objective of A10 SERT to fully release to the wild this framework when the research community this it is ready and agree that is the right course of action.

Sincerely,

Mike Thompson



# Project Objective

The primary objective of this project is to provide a platform that givees the ability for researchers to have a toolset
that enables the following:

1. Rapid prototyping and deployment of sensor type applications.
2. Sensor developers to controll the tcp stack and bypass kernel restrictions.
3. Emulation/Mimic of IoT devices and other internet application systems to enable global sensor distribution
   to reduce delta(t) to malwalre or botnet activity.
4. Enable dynamic appliation loading based on machine learning classifier for payloads.
5. Listen for application data on all ports and be able to discover behavior outside of statically
   assigned ports which may be missed.

Note: Documentation below this line will be update often. There may be slight drift.

# Install instructions. 

`cd /opt` 

`git clone https://github.com/a10networks/C2DEF.git`

`cd /opt/C2DEF`

`bash installer.sh`


# System Overview


***OS Requirement***
OS: Ubuntu 16.04 LTS


Each process has a source port BPF for a range of source ports to map the read_q to the appropriate processor socket. The main loop listens for ethernet frames. These frames are passed into a queue and then passed to the appropriate
protocol server. If the classifier is enabled and is trained the application with the matching lable will be selected.
If there is a miss with the classifier then a port match will be utilized to dynamically load the application.

Charmeleon -> protocol_server->XOR->classifier->application
                                |-->Port Match->application
                                |-->Default Application



# Applications

Applications that can be loaded are in the charmeleon.server.apps.enabled directory. These are dynamically loaded at
server startup. You can find an example for a tcp and udp examples:

```
[/server/apps/enabled/tcp_hello_world.py] TCP
[/server/apps/enabled/udp_hello_world.py] udp
```

There are several items that are required for the template to function and load.
The primary entrypoint is the class Main() in module. the method recv_data is the primary method that will be invoked
when the stack has data. There are specific configuration parameters that are required:
This is for protocol classification. However if classifier is set to classify_unknown in the configuration this value is ignored.
`self.protocol = <tcp||udp>``
`self.port = <expected port or port range> example: self.port = range(1-65535) or self.port=any`

The labels var is specifically to match this application to the classifier. If there is a classification with this label
then this app will be invoked unless there is more than one.
`self.labels = ["Hello World"]``

If there is a tie this priority is utilized to break it. Lowest priority wins.
`self.priority = 1`

If match IP is set to True this will cause the priority to be set by the folowing commands
`self.match_ip = True`

IPv4 address or cidr block
`self.match_list = ['192.168.2.1']``
Priority after ip list match.
`self.pri_match_ip = 255`

TCP Flags can be set to you can control the behavior of the application. Available Flags are S,A,P,F. You can combind flags.
tcp_flags = ['R', 'A']

If the payloaded being sent is greater than the config.MSS value which is defaulted to 1460 then the payload is buffered accordingly.
data that is returned should be returned as a try string in order to avoid errors. If it is packed data this will be addressed in a future build.

The call_back is of the call which is the loaded stack.

For TCP applications the following methods are available.
```
    callback.SEND_RST() <- tcp reset flag is set.
    callback.SEND_RST_ACK() <- tcp reset and ack flags are set.
    callback.SEND_FIN_ACK() <- tcp fin and ack flags are set.
    callback.SEND_FIN_PSH_ACK(data) <- tcp fin, push and ack flags are set.
    callback.SEND_ACK() <- tcp ack the data again, right now we ack every packet this needs to be optimized.
    callback.SEND_SYN_ACK()
    callback.SEND_DATA(self, data)
    callback.chunksdata(s)
```

If you would like to overide the stack and send multiple packets based on your application logic
you can utilize the following example:

```
to_send = len(mydata)
if to_send > self.config.MSS:
    buffer = callback.chunkdata(mydata)
    while to_send > 0:
        d = buffer.next()
        to_send = to_send - len(d)
        self.SEND_DATA(d)
```

###Template for TCP Application:

```
class Main():

    def __init__(self):
        self.protocol = 'tcp'
        self.port = 8080
        self.labels = ["Hello World"]
        self.priority = 1
        self.match_ip = True
        self.match_list = ['192.168.2.1']
        self.pri_match_ip = 255

    def recv_data(self, data, pkt, select_by, app_label, callback=None):

        '''
        when data is recieved it is on a per packet basis you will have to decide what
        you can choose to store the data for evaluation in the future. This class is initialized for the TCB object so it will persist.
        :param data:
        :return:
        '''

        tcp_flags = ['R', 'A']
        try:
            print "I WAS SELECTED BY", select_by, "AND NOW RETURNING with flags", tcp_flags
            return (self.do_some_stuff('Hello World'), tcp_flags)
        except:
            traceback.print_exc()



    def do_some_stuff(self, data):
        return ('HI YOU FROM HELLO WORLD1', None)
```


Classifier
----------

The classifier is the core of the system. It has been tunned to best fit single packet payloads. Currenly it is a one-vs-all utilizing a linearSVC
However, future classifiers will be made available once they are validated against real world traffic.
The road map includeds application reenforcement. This will allow the app to tel the engine that the prediction was
correct or specify a better lable in the training set.

```
{'steps': [('vectorizer', CountVectorizer(analyzer=u'word', binary=False, decode_error=u'strict',
        dtype=<type 'numpy.int64'>, encoding=u'utf-8', input=u'content',
        lowercase=True, max_df=1.0, max_features=None, min_df=1,
        ngram_range=(1, 1), preprocessor=None, stop_words=None,
        strip_accents=None, token_pattern=u'(?u)\\b\\w\\w+\\b',
        tokenizer=None, vocabulary=None)), ('tfidf', TfidfTransformer(norm=u'l2', smooth_idf=True, sublinear_tf=False,
         use_idf=True)), ('clf', OneVsRestClassifier(estimator=LinearSVC(C=1.0, class_weight=None, dual=True, fit_intercept=True,
     intercept_scaling=1, loss='squared_hinge', max_iter=1000,
     multi_class='ovr', penalty='l2', random_state=None, tol=0.0001,
     verbose=0),
          n_jobs=1))]}
```

***Training Data***

In order to load training data, the file needs to be placed in server.training.enabled directory. It myst be a .py extension and contain a json format as stated below.

```samples = [
{"payload":'Hello World',
     "labels":["Hello World"]}
]
````
Payload is required to be a string or a bytearray.
The labels key is a list of labels that apply to the sample. Each file can have multiple samples.

Trainging data is the core of the systems functinoality.
After testing several classification models the best performing and most accurate in predictions was the one-vs-all classifier.
The

```
<module 'server.training.enabled.avtech_reaper_detect' from '/Users/mthompson/PycharmProjects/chameleon/server/training/enabled/avtech_reaper_detect.pyc'>
<module 'server.training.enabled.dlink_reaper_detect' from '/Users/mthompson/PycharmProjects/chameleon/server/training/enabled/dlink_reaper_detect.pyc'>
<module 'server.training.enabled.jaws_reaper_detect' from '/Users/mthompson/PycharmProjects/chameleon/server/training/enabled/jaws_reaper_detect.pyc'>
<module 'server.training.enabled.linksys_reaper_detect' from '/Users/mthompson/PycharmProjects/chameleon/server/training/enabled/linksys_reaper_detect.pyc'>
<module 'server.training.enabled.NetGear_reaper_detect' from '/Users/mthompson/PycharmProjects/chameleon/server/training/enabled/NetGear_reaper_detect.pyc'>
<module 'server.training.enabled.vacron_reaper_detect' from '/Users/mthompson/PycharmProjects/chameleon/server/training/enabled/vacron_reaper_detect.pyc'>
<module 'server.training.enabled.wificam_reaper_detect' from '/Users/mthompson/PycharmProjects/chameleon/server/training/enabled/wificam_reaper_detect.pyc'>
Classifier Labels [['reaper-avtech'], ['reaper-dlink-dr600'], ['reaper-dlink-dr8'], ['reaper-jaws'], ['reaper-linksys'], ['reaper-netgear'], ['reaper-netgear-DGN1000'], ['reaper-vacron'], ['reaper-wificam']]
```

Default Configuration Params
----------------------------

The configuration file must be named config.py and located in teh server directory.

Most configuration parameters are native python list and strings. For port ranges you can utilize the range(1024,65535)
indicate the range of ports for the given configuration parameter.
For ip adderess ranges you can utilize a CIDR BLOCK.

There may be some commands that are implemented but not functional due to the feature not available. Think of this as a future.

**Default config params**

This section is for packet filtering...
```
ip_block =  []
ip_proto_permit =  [6, 17]
tcp_block_port =  []
udp_block_port =  []
set_iptables_rst_rule =  True
```
For obvious network constraints.

***MTU/MSS***

```
MSS = 1460
MTU = 1500
```

This is to configure filters for the classifier.

***classifier config***

```
classifier_ignore_ip =  []
classifier_ignore_port =  []
classifier_ip_proto =  [6, 17]
classifier_limit_prediction_data =  500
classify_unknown =  True
load_classifier =  <object>
```

***Default Applications Params***

```
load_apps =  True
```

***Elastic Search Params***

es_auth_url = None
es_base_url = None
es_password = None
es_username = None



**Not implemented at this time... ***

Everything below this line is not implemented....

````
default_app =  None
pcap_dir =  /tmp/pcap
pcap_max_size =  1024
pcap_split_on_port =  True
sniffer_apps_only =  False
sniffer_enabled =  False
sniffer_ignore_ip =  []
sniffer_ignore_port =  []
sniffer_ip_proto =  []
sniffer_non_apps =  True
sniffer_only =  False
syslog_enable =  False
syslog_server =  []
log_dir =  /var/log/
````


`Notes:` At this time the UDP server infrastructure is disabled. This is because the TCP traffic is much more exciting to me ;)
