# encoding=utf-8
import pymongo
import json
import datetime


class ParseMasscan(object):
    def __init__(self):
        self.results_filename = '/home/ti/data/masscan/ports.json'
        with open(self.results_filename, 'r') as f:
            self.data = json.load(f)

        self.masscan_ports = pymongo.MongoClient('localhost', 27017)['virustotal']['masscan']
        self.doc = {}

    def check(self):
        for d in self.data:
            self.doc.clear()
            self.doc['ip'] = d.get('ip')
            ts = d.get('timestamp')
            ts = datetime.datetime.utcfromtimestamp(float(ts))
            timestamp = ts.strftime('%Y-%m-%d %H:%M:%S')
            self.masscan_ports.update({'ip': d.get('ip')}, {'$addToSet': {'ports': d.get('ports')[0].get('port')},
                                                            '$set': {'timestamp': timestamp}},
                                      upsert=True)
            print '[Upsert success: %s: %s]' % (d.get('ip'), d.get('ports')[0].get('port'))


if __name__ == '__main__':
    ParseMasscan().check()
