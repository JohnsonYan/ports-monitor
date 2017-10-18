# encoding=utf-8
import shodan


class ShodanApi:
    """
    dict = {
            'city':
            'region_code':
            'os':
            'tags':
            'ip':
            'isp':
            'area_code':
            'dma_code':
            'last_update':
            'country_code3':
            'country_name':
            'hostnames':
            'postal_code':
            'longitude':
            'country_code':
            'ip_str':
            'latitude':
            'org':
            'data':
            'asn':
            'ports':
            'banner':[[port,transport,product],...]
    }
    """
    def __init__(self):
        self._shodan_api_key = "i964p9KFNScCwGLovxm1V2rYIIpUsl8T"
        self._api = shodan.Shodan(self._shodan_api_key)
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
                self.info[key] = value
            for item in host['data']:
                self.banner.append([item.get('port', 'n/a'), item.get('transport', 'n/a'), item.get('product', 'n/a')])
            self.info['banner'] = self.banner

            return self.info
        except shodan.APIError, e:
            print 'Error: %s [IP: %s]' % (e, ip)



    def get_ports(self):
        return self.info['ports']

    def get_banner(self):
        return self.info['banner']


if __name__ == '__main__':
    S = ShodanApi()
    S.search('173.247.244.12')
    print str(S.get_ports())



