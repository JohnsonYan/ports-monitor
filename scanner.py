# encoding=utf-8
import time
import datetime
import Queue
import pymongo
import shodan_api


class Scanner(object):
    def __init__(self):
        # shodan api,通过轮询使用，使每秒钟一条的请求速度限制降低
        self.keys = ['RNrOvCRgqFyLdmg0Jxtv8EfyIE2ZA4wi',
                     'i964p9KFNScCwGLovxm1V2rYIIpUsl8T',
                     'b8OSJfnRS7u65NZ6DHFKPnHYNhh4mqSf',
                     '8zFmb4ZwKI4kH39nE5eL7FHdGRydkM3g']
        self.api_queue = Queue.Queue()
        for key in self.keys:
            self.api_queue.put(shodan_api.ShodanApi(key))

        # aws mongodb config
        self.domain = pymongo.MongoClient('34.209.173.8', 27017)['virustotal']['domain']
        # mongodb config
        self.ports = pymongo.MongoClient('localhost', 27017)['virustotal']['shodan_scan']

    def shodan_scan(self):
        try:
            # 获取到去重后的，由domain得来的IP
            ips = self.domain.distinct('iplist.ip', {'tags': {'$not': {'$in': ['sinkhole']}}})

            for ip in ips:
                # sleep, api使用频率限制
                time.sleep(1.5 / len(self.keys))

                # 不想扫描已有结果的数据时
                if self.ports.find({'ip_str': ip}).count() > 0:
                    print 'skip %s, because this ip has been scaned by shodan api' % ip
                    continue

                # 如果发现当前扫描对象的status为201，说明已经由nmap处理，故不继续处理
                if self.ports.find({'status': '201', 'ip_str': ip}).count() > 0:
                    print 'skip %s, because this ip has been scaned by nmap/masscan' % ip
                    continue

                api = self.api_queue.get()
                info = api.search(ip)
                # 将使用完毕的api重新放入队列中
                self.api_queue.put(api)
                
                # 处理数据
                if info is None:
                    continue
                self.ports.update({'ip_str': ip},
                                  {'$set': info},
                                  upsert=True)
                print '[Upsert Success. IP: %s]' % ip

            print '[FINISH shodan scan]'
        except Exception as e:
            print e.message

    def schedule(self):
        """
        定时任务
        :return:
        """
        # time
        start_time = 3
        if datetime.datetime.now().hour == start_time:
            self.shodan_scan()


if __name__ == '__main__':
    print '[Running...]'
    scan = Scanner()
    while True:
        try:
            # 每小时检查一次是否可以开始任务
            scan.schedule()
            time.sleep(60*60)
        except Exception as msg:
            print msg
