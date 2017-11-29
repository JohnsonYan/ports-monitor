# encoding=utf-8
import pymongo
import wyportmap_mongo


class NmapScanner(object):
    def __init__(self):
        # mongodb config
        self.domain_ip_ports = pymongo.MongoClient('localhost', 27017)['virustotal']['domain-ip-ports']

    def nmap_scan(self):
        try:
            count = 0
            ips = self.domain_ip_ports.distinct('ip_str', {'status': '101'})
            for ip in ips:
                wyportmap_mongo.run_wyportmap(ip)
                # status 201 表示已被nmap扫描
                self.domain_ip_ports.update({'status': '101', 'ip_str': ip},
                                            {'$set': {'status': '201'}})
                count += 1
                print '[need to scan: %d] [finish scan: %d]' % (len(ips), count)
            print "[FINISH nmap scan]"
        except Exception as e:
            print e.message


if __name__ == '__main__':
    scan = NmapScanner()
    scan.nmap_scan()
