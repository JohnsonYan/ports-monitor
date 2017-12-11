# encoding=utf-8
import time
import pymongo


def output():
    try:
        domain_ip_ports = pymongo.MongoClient('localhost', 27017)['virustotal']['domain-ip-ports']
        ips = domain_ip_ports.distinct('ip_str', {'status': '101'})
        filename = 'libmasscan/data/input-%s.txt' % time.strftime('%Y-%m-%d', time.localtime(time.time()))

        with open(filename, 'w') as f:
            for ip in ips:
                f.write('%s\n' % str(ip))
                # 更新status 201，表示已被提取出来，交给masscan处理
                domain_ip_ports.update({'ip_str': ip}, {'$set': {'status': '201'}})
        print '[info]Output input.txt'

    except Exception as msg:
        print '[error]%s' % msg


if __name__ == '__main__':
    output()
