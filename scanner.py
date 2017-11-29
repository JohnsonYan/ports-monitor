# encoding=utf-8
import time
import datetime
import pymongo
import shodan_api


class Scanner(object):
    def __init__(self):
        # aws mongodb config
        self.domain = pymongo.MongoClient('34.209.173.8', 27017)['virustotal']['domain']
        # mongodb config
        self.ports = pymongo.MongoClient('localhost', 27017)['virustotal']['domain-ip-ports']

    # DONE:1、编写代码处理request limit reached错误,遇到这种错误可以等待几分钟再请求,这个功能在shodan_api中完成了
    # 2、编写代码处理Error: No information available for that IP. 将这类ip放入单独的列表，交给nmap处理
    def shodan_scan(self):
        try:
            api = shodan_api.ShodanApi()

            # 获取到去重后的，由domain得来的IP
            ips = self.domain.distinct('iplist.ip', {'tags': {'$not': {'$in': ['sinkhole']}}})

            for ip in ips:
                # 如果发现当前扫描对象的status为201，说明已经由nmap处理，故不继续处理
                if self.ports.find({'status': '201', 'ip_str': ip}).count() > 0:
                    continue

                # 不想扫描已有结果的数据时
                if self.ports.find({'ip_str': ip}).count() > 0:
                    continue

                # shodan_api request limit
                time.sleep(1.5)
                info = api.search(ip)
                if info is None:
                    continue

                self.ports.update({'ip_str': ip},
                                  {'$set': info},
                                  upsert=True)
                print '[Update Success. IP: %s]' % ip
                print '[FINISH shodan scan]'
        except Exception as e:
            print e.message


if __name__ == '__main__':
    Scanner().shodan_scan()
