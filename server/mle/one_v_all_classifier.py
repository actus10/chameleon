# -*- coding: utf-8 -*-
# Copyright 2017, A10 Networks
# Author: Mike Thompson: @mike @t @a10@networks!com

import binascii
import re
import traceback
import time
import numpy as np
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.feature_extraction.text import TfidfTransformer
from sklearn.multiclass import OneVsRestClassifier
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import MultiLabelBinarizer
from sklearn.svm import LinearSVC


re1 = re.compile(r'(?:[\d]{1,3})\.(?:[\d]{1,3})\.(?:[\d]{1,3})\.(?:[\d]{1,3})')
re2 = re.compile(r':(?:[0-9][1,5])$')

print "Classifier Imports try 1"
try:
    from server.utilities.loader import loader

    MODULE_TRAINING = loader()
    MODULE_TRAINING = MODULE_TRAINING.load_training_data()
    import config
except:
    print "Classifier Imports try 2"
    try:
        from utilities.loader import loader

        MODULE_TRAINING = loader()
        MODULE_TRAINING = MODULE_TRAINING.load_training_data()
        import config
    except:
        print "Classifier Imports try failed"
        traceback.print_exc()


class Classifier():
    def __init__(self):
        self.run()

    def run(self):
        self.disabled = False
        data = []
        labels = []
        for i in MODULE_TRAINING:
            print i
            try:
                for h in i.samples:
                    sample = h['payload'].decode('unicode_escape').encode('utf-8')
                    if isinstance(h['payload'], bytearray):
                        sample = binascii.b2a_qp(h['payload'])
                    sample = re.sub(re1, 'XXX.XXX.XXX.XXX', sample.rstrip())
                    sample = re.sub(re2, 'XXXX', sample.rstrip())
                    data.append(sample)
                    labels.append(h['labels'])
            except:
                print("Could not load taining data for {module}".format(module=i.__name__))
        if len(data) == 0 or (len(data) != len(labels)):
            self.disabled = True
            return None

        X_train = np.array(data)
        y_train_text = labels
        print "Classifier Labels", labels
        self.mlb = MultiLabelBinarizer()
        Y = self.mlb.fit_transform(y_train_text)

        self.classifier = Pipeline([
            ('vectorizer', CountVectorizer(token_pattern=r"(?u)\b\w\w+\b",
                                           ngram_range=config.ngram_range, analyzer=config.analyzer,
                                           max_df=config.max_df, min_df=config.min_df, max_features=config.max_features,
                                           vocabulary=config.vocabulary, binary=config.binary, )),
            ('tfidf', TfidfTransformer()),
            ('clf',
             OneVsRestClassifier(LinearSVC(multi_class=config.multi_class, penalty=config.penalty, loss=config.loss, dual=config.dual, tol=config.tol,
                                           C=config.C, fit_intercept=config.fit_intercept,
                                           intercept_scaling=config.intercept_scaling, class_weight=config.class_weight, verbose=config.verbose,
                                           random_state=config.random_state, max_iter=config.max_iter), n_jobs=-2))])

        self.classifier.fit(X_train, Y)
        print self.classifier.__dict__
        self.test_against_self()

    def predict(self, sample):

        try:
            print "Starting Prediction"

            if self.disabled is True:
                # print "classifier is disabled"
                return None
            sample = re.sub(re1, 'XXX.XXX.XXX.XXX', sample.rstrip())
            sample = re.sub(re2, 'XXXX', sample.rstrip())
            if isinstance(sample, bytearray):
                # print "TRUE"
                data = binascii.b2a_qp(sample)
            # print "Classifier data", data
            
            x = np.array([sample.decode('unicode_escape').encode('utf-8')])
            t = time.time()
            all_labels = self.mlb.inverse_transform(self.classifier.predict(x))
            print "Prediction Time:", time.time() - t
            l = []
            for item, labels in zip(x, all_labels):
                #print labels, sample
                l.append(labels)
            return l
        except:
            traceback.print_exc()
            

    def test_against_self(self):
        for i in MODULE_TRAINING:
            for j in i.samples:
                payload = j['payload']
                label = j['labels']

                p_label = self.predict(payload)
                try:
                    print "Testing", label[0], "against", p_label[0][0]
                    assert (True if label[0] == p_label[0][0] else False)
                    print "RESULT:", True

                except:
                    try:
                        print("RESULT: FALSE for labels:", label[0], "against", p_label[0][0],
                              "\nCheck Training Data for:", i)
                    except:
                        print "Failed for module:", i


if __name__ == "__main__":
    x = Classifier()


