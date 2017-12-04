# encoding=utf-8
import pymongo


def output():
    domain_ip_ports = pymongo.MongoClient('localhost', 27017)['virustotal']['domain-ip-ports']
    ips = domain_ip_ports.distinct('ip_str', {'status': '101'})
    count = 0
    with open('input.txt', 'w') as f:
        for ip in ips:
            f.write('%s\n' % str(ip))
            # 更新status 201，表示已被提取出来，交给masscan处理
            domain_ip_ports.update({'ip_str': ip}, {'$set': {'status': '201'}})
            count += 1

            # for test,be small
            # ~/data/masscan
            if count > 50:
                break

    print count


if __name__ == '__main__':
    output()