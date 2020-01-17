# check to set defaults under the covers for the config
try:
    import server.config as config
    from server.mle import one_v_all_classifier

except:
    try:
        import config
        from mle import one_v_all_classifier

    except BaseException as e:
        raise e


# from server.mle import one_v_all_classifier

class CheckConfig(object):
    def __init__(self):
        self.MSS = 1460
        self.MTU = 1500
        self.default_app = None
        self.ip_block = []
        self.ip_proto_permit = [6, 17]
        self.tcp_block_port = []
        self.udp_block_port = []
        self.default_app = False
        self.classifier = True
        self.classifier_limit_prediction_data = 500
        self.classifier_ignore_port = []
        self.classifier_model = None
        self.classifier_type = 'ovr'
        self.load_classifier = None
        # Remove threading from classifier due to inconsistencies.
        # self.load_classifier.start()
        self.classify_unknown = True
        self.classifier_ignore_ip = []
        self.load_apps = True
        self.classifier_ip_proto = [6, 17]
        self.sniffer_enabled = False
        self.sniffer_only = False
        self.sniffer_apps_only = False
        self.sniffer_non_apps = True
        self.sniffer_ignore_ip = []
        self.sniffer_ip_proto = []
        self.sniffer_ignore_port = []
        self.pcap_dir = "/tmp/pcap"
        self.pcap_split_on_port = True
        self.pcap_max_size = 1024
        self.log_dir = "/var/log/"
        self.syslog_enable = False
        self.syslog_server = []
        self.set_iptables_rst_rule = True
        self.es_auth_url = ""
        self.es_base_url = ""
        self.es_username = ""
        self.es_password = ""

        aws_get_meta_data = True

    def _merge(self):
        # print "Classifier config:", config.__dict__.get(classifer', self.classifier)
        # TODO: APP Futures
        config.__dict__['default_app'] = config.__dict__.get('default_app', self.default_app)
        config.__dict__['MSS'] = config.__dict__.get('MSS', self.MSS)
        config.__dict__['MTU'] = config.__dict__.get('MSS', self.MTU)

        # TODO: TCP/IP Futures
        config.__dict__['ip_block'] = config.__dict__.get('ip_block', self.ip_block)
        config.__dict__['ip_proto_permit'] = config.__dict__.get('ip_proto_permit', self.ip_proto_permit)
        config.__dict__['tcp_block_port'] = config.__dict__.get('tcp_block_port', self.tcp_block_port)
        config.__dict__['udp_block_port'] = config.__dict__.get('udp_block_port', self.udp_block_port)

        # TODO: Classifier Futures
        config.__dict__['classifer'] = config.__dict__.get('classifer', self.classifier)
        config.__dict__['classifier_ignore_ip'] = config.__dict__.get('classifier_ignore_ip',
                                                                      self.classifier_ignore_ip)
        config.__dict__['classify_unknown'] = config.__dict__.get('classify_unknown', self.classifier)
        config.__dict__['load_apps'] = config.__dict__.get('load_apps', self.load_apps)
        config.__dict__['classifier_ignore_port'] = config.__dict__.get('classifier_ignore_port',
                                                                        self.classifier_ignore_port)
        config.__dict__['classifier_ip_proto'] = config.__dict__.get('classifier_ip_proto', self.classifier_ip_proto)

        model = config.__dict__.get('classifier_model', self.classifier_model)
        print "TRY MODEL: ", model
        if model is not None:
            print "MODEL CONFIGURED: ", model
            if (config.__dict__.get('classifier_type', self.classifier_type)) == 'ml':
                print "MODEL LOADING STARTED....."
                config.__dict__['load_classifier'] = model_loader.classifier("mle/chamo/models/"+model)
                print "MODEL LOADED....."
            else:
                config.__dict__['load_classifier'] = config.__dict__.get('load_classifier',
                                                                         one_v_all_classifier.Classifier())
        else:
            config.__dict__['load_classifier'] = config.__dict__.get('load_classifier',
                                                                     one_v_all_classifier.Classifier())

        config.__dict__['classifier_limit_prediction_data'] = config.__dict__.get('classifier_limit_prediction_data',
                                                                                  self.classifier_limit_prediction_data)
        # TODO: SNIFFER Futures
        config.__dict__['sniffer_enabled'] = config.__dict__.get('sniffer_enabled', self.sniffer_enabled)
        config.__dict__['sniffer_only'] = config.__dict__.get('sniffer_only', self.sniffer_only)
        config.__dict__['sniffer_apps_only'] = config.__dict__.get('sniffer_apps_only', self.sniffer_apps_only)
        config.__dict__['sniffer_non_apps'] = config.__dict__.get('sniffer_non_apps', self.sniffer_non_apps)
        config.__dict__['sniffer_ignore_ip'] = config.__dict__.get('sniffer_ignore_ip', self.sniffer_ignore_ip)
        config.__dict__['sniffer_ip_proto'] = config.__dict__.get('sniffer_ip_proto', self.sniffer_ip_proto)
        config.__dict__['sniffer_ignore_ports'] = config.__dict__.get('sniffer_ignore_port', self.sniffer_ignore_port)
        config.__dict__['pcap_split_on_port'] = config.__dict__.get('pcap_split_on_port', self.pcap_split_on_port)
        config.__dict__['pcap_max_size'] = config.__dict__.get('pcap_max_size', self.pcap_max_size)

        # TODO: Logging Futures
        config.__dict__['log_dir'] = config.__dict__.get('log_dir', self.log_dir)
        config.__dict__['syslog_enable'] = config.__dict__.get('syslog_enable', self.syslog_enable)
        config.__dict__['syslog_server'] = config.__dict__.get('syslog_server', self.syslog_server)
        # Elastic Search
        # TODO: IPtables Enhancements
        config.__dict__['set_iptables_rst_rule'] = config.__dict__.get('set_iptables_rst_rule',
                                                                       self.set_iptables_rst_rule)
        config.__dict__.get('udp_block_port', self.udp_block_port)
        newconfig = type('config', (object,), dict(**config.__dict__))
        return config


if __name__ == "__main__":
    x = CheckConfig()._merge()
    print id(config)
    print config.__dict__.get('udp_block_port')
    print type(x)
    print x.udp_block_port
    # print config.__dict__.get('udp_block_port', self.udp_block_port)

    # x.load_classifier = None
    # for k,v in x.__dict__.items():
    #     print k,"= ",v
