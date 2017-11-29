# encoding=utf-8
import shodan
import time


class ShodanApi:
    def __init__(self):
        self._shodan_api_key = "i964p9KFNScCwGLovxm1V2rYIIpUsl8T"
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
            for item in host['data']:
                self.banner.append([item.get('port', 'n/a'), item.get('transport', 'n/a'), item.get('product', 'n/a')])
            self.info['banner'] = self.banner
            self.info['status'] = self.status['OK']

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
    S = ShodanApi()
    S.search('173.247.244.12')
    print str(S.get_ports())
