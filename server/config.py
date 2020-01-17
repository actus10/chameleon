# -*- coding: utf-8 -*-
# Copyright 2017, A10 Networks
# Author: Mike Thompson: @mike @t @a10@networks!com

#CountVectorizer Tuning params
token_pattern=r"(?u)\b\w\w+\b"
ngram_range=(1, 2)
analyzer='char_wb'
max_df=1.0
min_df=0.0
max_features=None
vocabulary=None
binary=False

#OVR->LinearSVC Tuning Params.
multi_class='ovr'
penalty='l2'
loss='squared_hinge'
dual=False
tol=1e-7
C=1.0
fit_intercept=False
intercept_scaling=1e3
class_weight='balanced'
verbose=1
random_state=42
max_iter=1000

# Main Config
# Defaults

mgmt_ip_list =  []
if_n = 'en0'
multi_nic = False
ip_proto_permit = [6, 17]
ip_ignore_ip = []
tcp_block_port = [22]
udp_block_port = []
# ['classifier']
classifier = True
# for range needs to be in cidr block
classifier_ignore_ip = ['192.168.1.1', '172.16.0.0/16']
classify_unknown = True
#if there is a trained classifier model then speficy the name in: mle/models/
classifier_model = ""

#types can be ml=== model loader or ovr which implies load trying data.
# Both classifiers are ovr but one is precompiled vs. trained locally.
#classifier_type = "ml"
classifier_type = 'ovr'
# for port range utilize the range command
classifier_ignore_port = [22]
classifier_ip_proto = [6, 17]
# if you have a payload_sample_map an app to.
# ['APPS']
# load_apps = False

# Elastic Search
username = ""
password = ""
base_url = ""
auth_url = "/_xpack/security/_authenticate"
oauth_url = "/_xpack/security/oauth2/token"

