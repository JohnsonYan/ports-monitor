# encoding=utf-8
import pymongo
import redis
import wyportmap_mongo

# 101 shodan未解析 -> 201 交由masscan扫描 -> 200 交由nmap扫描


class NmapScanner(object):
    def __init__(self):
        self.count = 0
        # mongodb config
        # self.shodan_scan = pymongo.MongoClient('localhost', 27017)['virustotal']['shodan_scan']
        self.masscan = pymongo.MongoClient('localhost', 27017)['virustotal']['masscan']
        # redis config
        self.redis_queue = redis.Redis(host='localhost', port=6379, decode_responses=True, db=0)

    def nmap_scan(self):
        """
        调用wyportmap_mongo.py的nmap扫描程序
        :return:
        """
        try:
            ip = self.redis_queue.blpop('ip')
            wyportmap_mongo.run_wyportmap(str(ip[1]))
            # status 200 表示已交由nmap扫描
            self.masscan.update({'ip': str(ip[1])}, {'$set': {'status': '200'}})
            self.count += 1
            print '[debug]finish [%d] %s' % (self.count, str(ip[1]))
        except Exception as msg:
            print '[error]%s' % msg


if __name__ == '__main__':
    scan = NmapScanner()
    while True:
        scan.nmap_scan()
