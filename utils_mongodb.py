# encoding=utf-8
import pymongo


class UtilsMongodb(object):
    """
    工具类
    """

    def __init__(self):
        self.host = 'localhost'
        self.port = 27017
        self.client = pymongo.MongoClient(self.host, self.port)
        self.db = self.client['test']
        self.shodan_data = self.db['shodan_data']

    def insert_one(self, data):
        self.shodan_data.insert(data)

    def find_for_nmap(self):
        return self.shodan_data.find({'status': '101'})

    def update_status(self, domain, code):
        self.shodan_data.update({'original_domain': domain},
                                {'$set': {'status': str(code)}},multi=True)
        print 'updata success'
