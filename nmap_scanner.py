# encoding=utf-8
import pymongo
import wyportmap_mongo

# 101 shodan未解析 -> 201 交由masscan扫描 -> 200 交由nmap扫描


class NmapScanner(object):
    def __init__(self):
        # mongodb config
        self.shodan_scan = pymongo.MongoClient('localhost', 27017)['virustotal']['shodan_scan']
        self.masscan = pymongo.MongoClient('localhost', 27017)['virustotal']['masscan']

    def nmap_scan(self):
        try:
            count = 0
            # 寻找没有status字段的，表示该IP未被nmap处理
            ips = self.shodan_scan.find({'status': {'$exists': False}}).batch_size(2)
            for ip in ips:
                wyportmap_mongo.run_wyportmap(str(ip.get('ip')))
                # status 200 表示已交由nmap扫描
                self.masscan.update({'ip': ip.get('ip')}, {'$set': {'status': '200'}})
                count += 1
                print '[need to scan: %d] [finish scan: %d]' % (ips.count(), count)
            print "[FINISH nmap scan]"
        except Exception as e:
            print e.message


if __name__ == '__main__':
    scan = NmapScanner()
    scan.nmap_scan()
