# encoding=utf-8
import shodan
import time


class ShodanApi:
    def __init__(self, api):
        self._shodan_api_key = api
        self._api = shodan.Shodan(self._shodan_api_key)
        self.status = {'No information available for that IP': '101',
                       'Invalid IP': '102',
                       'Unable to parse JSON response': '103',
                       'Other error': '199',
                       'OK': '200',
                       }
        self.info = {}
        self.banner = []

    def _clear(self):
        self.info.clear()
        self.banner = []

    def search(self, ip):
        """
        调用shodan的host(ip)接口，查询相关IP的详细信息
        解析到info字典中，返回
        :param ip: 一条IP地址
        :return:
        """
        # 每次调用search应清空保存着上一条结果的info,banner
        self._clear()
        try:
            # Search Shodan
            ip = ip.strip()
            host = self._api.host(ip)
            # Parse data
            for key, value in host.items():
                # filter data keyword
                if key == 'data':
                    continue
                self.info[key] = value
            for item in host.get('data'):
                self.banner.append({'port': item.get('port', None),
                                    'transport': item.get('transport', None),
                                    'product': item.get('product', None),
                                    'devicetype': item.get('devicetype', None),
                                    'timestamp': item.get('timestamp', None),
                                    'tags': item.get('tags', None),
                                    'server': item.get('http', {}).get('server', None),
                                    'module': item.get('_shodan', {}).get('module', None)})

            self.info['banner'] = self.banner
            self.info['status'] = self.status['OK']
            self.info['timestamp'] = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))

            return self.info
        except shodan.APIError as e:
            if 'Invalid IP' in e.value:
                # mostly IP 127.0.0.1
                self.info['status'] = self.status['Invalid IP']
            elif 'No information available for that IP' in e.value:
                self.info['status'] = self.status['No information available for that IP']
            elif 'Request limit reached' in e.value:
                print 'Request limit reached, please wait a moment......'
                time.sleep(15)
                self.search(ip)
            elif 'Unable to parse JSON response' in e.value:
                self.info['status'] = self.status['Unable to parse JSON response']
            else:
                self.info['status'] = self.status['Other error']
            self.info['ip_str'] = ip
            print 'Error:', e.value, '[IP: %s]' % ip
            return self.info

    def get_ports(self):
        return self.info['ports']

    def get_banner(self):
        return self.info['banner']


if __name__ == '__main__':
    S = ShodanApi('8zFmb4ZwKI4kH39nE5eL7FHdGRydkM3g')
    S.search('173.247.244.12')
    print str(S.get_ports())
