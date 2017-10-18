# encoding=utf-8

import os
import socket
import nmap
import shodan_api


class Scanner(object):
    """
    扫描器类
    """

    def __init__(self):
        self.ip_list = {}
        self.filename_list = 'malware-domains-list'

    def scan_ip_from_shodan(self):
        self._get_ip_list()
        api = shodan_api.ShodanApi()
        for domain, ips in self.ip_list.items():
            for ip in ips:
                info = api.search(ip)
                if info is None:
                    continue
                info['original_domain'] = domain
                # for key,value in info.items():
                #     if key != 'data':
                #         print key,':',value
    # TODO: 判断是否已有文件存在，存在且不为空则表示已经扫描过该文件
    def host_discory(self, filename):
        """
        发现所有存活的(host up)主机，暂且将扫描结果存入文件中
        :param filename: 存储着域名的文件，一行一个域名
        :return: 1:success 0:fail
        """
        nm = nmap.PortScanner()
        command = '-sP -PE -PP -PS21,22,23,25,80,113 -PA80,113,443 --source-port 53 -T4 -iL %s --min-rate175 --max-rate 300 --max-scan-delay 10' % filename

        dirname = 'results'
        if not os.path.exists(dirname):
            os.mkdir(dirname)

        f = open(os.path.join(dirname, os.path.basename(filename)), 'w')

        nm.scan(
            arguments=command,
            sudo=True,
        )

        for host in nm.all_hosts():
            # format: host,ip,status
            f.write('%s,%s,%s\n' % (host, nm[host].hostname(), nm[host].state()))
            # print 'Host : %s (%s) Status : %s' % (host, nm[host].hostname(), nm[host].state())

        f.close()


    # TODO: socket.gethostbyname_ex返回三元组(hostname, aliaslist, ipaddrlist)，其中aliaslist暂未使用，后期有需要再添加
    def _get_ip_list(self):
        """
        translate domain name to ip
        :return: a dict = {
                            'domain name1':['ip1','ip2',...],
                            'domain name2':['ip1','ip2',...],
                            ...
                        }
        """
        # get filename list from file : self.filename_list
        filename_list = []
        with open(self.filename_list, 'r') as f:
            for line in f:
                filename_list.append(line.strip())
                break #TEST-----------------------------------------------------------delete it remember
        # read each file from filename list
        # translate each domain into ip
        for filename in filename_list:
            with open(filename, 'r') as f:
                for line in f:
                    try:
                        ip = socket.gethostbyname_ex(line.strip())
                    except socket.error as msg:
                        continue
                    if ip is not None:
                        self.ip_list[ip[0]] = ip[2]



def main():
    scanner = Scanner()
    scanner.scan_ip_from_shodan()



if __name__ == '__main__':
    main()
