# encoding=utf-8
import re
import time
import pymongo


class AddTags(object):
    def __init__(self):
        self.shodan = pymongo.MongoClient('127.0.0.1', 27017)['virustotal']['shodan_scan']
        self.ip_tags = pymongo.MongoClient('127.0.0.1', 27017)['virustotal']['ip_tags']

        self.iot_product_regex = [
            # 摄像头
            '.*DVR.*',
            '.*D-Link.*',
            '.*Avtech.*',
            '.*Netwave.*',
            '.*GeoVision.*',
            '.*Vivotek.*',
            '.*Axis 207W Network Camera ftpd.*',
            # 路由器们
            '.*DD-WRT.*',
            '.*Cisco.*'
            '.*Linksys.*'
        ]
        self.iot_server_regex = [
            # 摄像头
            '.*NVR Webserver.*',
            '.*Hikvision-Webs.*',
            '.*SQ-WEBCAM.*',
            '.*Avtech.*',
            '.*IPCamera_Logo.*',
            '.*U S Software Web Server.*',
            '.*yawcam.*',
            '.*Yawcam.*',
            '.*MJPG-Streamer/0.2.*',
            '.*go1984.*',
            '.*UBNT Streaming Server v1.2.*',
            '.*Pan/Tilt.*',
            '.*BlueIris-HTTP/1.1.*',
            '.*IP Webcam Server.*',
            '.*i-Catcher Console.*',
            '.*GeoHttpServer.*',
            '.*Android Webcam Server.*',
            '.*GoAhead-Webs.*',
            '.*ADH-Web.*',
            '.*VB100.*',
            '.*Linux/2.x UPnP/1.0 Avtech/1.0.*',
            '.*Camera Web Server.*',
            '.*Cam.*',
            '.*webcamXP.*'
        ]
        self.iot_module_regex = [
            # 工控协议
            'modbus',
            's7',
            'dnp3',
            'fox',
            'bacnet',
            'ethernetip',
            'ethernetip-udp',
            'general-electric-srtp',
            'hart-ip-udp',
            'pcworx',
            'melsec-q-tcp',
            'omron-tcp',
            'redlion-crimson3',
            'codesys',
            'iec-104',
            'proconos',
            'moxa-nport'
        ]

        # banner.product trojan
        self.trojan_tags_reobj = re.compile('.*trojan.*', re.I)

        # 编译正则表达式，将编译后的正则匹配对象放入下面的list中供匹配时使用
        # banner.product iot
        self.iot_product_reobj = []
        # banner.server iot
        self.iot_server_reobj = []
        # banner.module iot
        self.iot_module_reobj = []
        # banner.devicetype iot
        self.iot_devicetype_reobj = re.compile('.*webcam.*', re.I)

        for pattern in self.iot_product_regex:
            self.iot_product_reobj.append(re.compile(pattern, re.I))
        for pattern in self.iot_server_regex:
            self.iot_server_reobj.append(re.compile(pattern, re.I))
        for pattern in self.iot_module_regex:
            self.iot_module_reobj.append(re.compile(pattern, re.I))

    def add_tags_iot(self):
        """
        给IP打iot标签
        :return:
        """
        self._check_product()
        self._check_server()
        self._check_module()
        self._check_devicetype()

    def _check_product(self):
        """
        匹配banner.product字段，在其自有的tags基础上再打上iot标签
        :return:
        """
        count = 0
        for reobj in self.iot_product_reobj:
            cursor = self.shodan.find({'status': '200', 'banner.product': reobj})
            if cursor is not None:
                for cur in cursor:
                    doc = {'ip': cur.get('ip_str'),
                           'inserttime': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time())),
                           'detecttime': cur.get('timestamp')}
                    tags = cur.get('tags')
                    tags.append('iot')

                    self.ip_tags.update({'ip': cur.get('ip_str')},
                                        {'$set': doc,
                                         '$addToSet': {'tags': {'$each': list(tags)}}},
                                        upsert=True)
                    count += 1
        print '[iot]banner.product: %d' % count

    def _check_server(self):
        """
        匹配banner.server字段，在其自有的tags基础上再打上iot标签
        :return:
        """
        count = 0
        for reobj in self.iot_server_reobj:
            cursor = self.shodan.find({'status': '200', 'banner.server': reobj})
            if cursor is not None:
                for cur in cursor:
                    doc = {'ip': cur.get('ip_str'),
                           'inserttime': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time())),
                           'detecttime': cur.get('timestamp')}
                    tags = cur.get('tags')
                    tags.append('iot')

                    self.ip_tags.update({'ip': cur.get('ip_str')},
                                        {'$set': doc,
                                         '$addToSet': {'tags': {'$each': list(tags)}}},
                                        upsert=True)
                    count += 1
        print '[iot]banner.server: %d' % count

    def _check_module(self):
        """
        匹配banner.module字段，在其自有的tags基础上再打上iot标签
        :return:
        """
        count = 0
        for reobj in self.iot_module_reobj:
            cursor = self.shodan.find({'status': '200', 'banner.module': reobj})
            if cursor is not None:
                for cur in cursor:
                    doc = {'ip': cur.get('ip_str'),
                           'inserttime': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time())),
                           'detecttime': cur.get('timestamp')}
                    tags = cur.get('tags')
                    tags.append('iot')

                    self.ip_tags.update({'ip': cur.get('ip_str')},
                                        {'$set': doc,
                                         '$addToSet': {'tags': {'$each': list(tags)}}},
                                        upsert=True)
                    count += 1

        print '[iot]banner.module: %d' % count

    def _check_devicetype(self):
        """
        匹配banner.devicetype字段，在其自有的tags基础上再打上iot标签
        :return:
        """
        count = 0
        cursor = self.shodan.find({'status': '200', 'banner.devicetype': self.iot_devicetype_reobj})
        for cur in cursor:
            doc = {'ip': cur.get('ip_str'),
                   'inserttime': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time())),
                   'detecttime': cur.get('timestamp')}
            tags = cur.get('tags')
            tags.append('iot')

            self.ip_tags.update({'ip': cur.get('ip_str')},
                                {'$set': doc,
                                 '$addToSet': {'tags': {'$each': list(tags)}}},
                                upsert=True)
            count += 1

        print '[iot]banner.devicetype: %d' % count

    def add_tags_shodan(self):
        """
        将shodan自带的tags加进来
        :return:
        """
        count = 0
        cursor = self.shodan.find({'status': '200', 'tags': {'$not': {'$size': 0}}})
        for cur in cursor:
            doc = {'ip': cur.get('ip_str'),
                   'inserttime': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time())),
                   'detecttime': cur.get('timestamp')}
            tags = cur.get('tags')

            self.ip_tags.update({'ip': cur.get('ip_str')},
                                {'$set': doc,
                                 '$addToSet': {'tags': {'$each': list(tags)}}},
                                upsert=True)
            count += 1

        print '[shodan tags]tags: %d' % count

    def add_tags_trojan(self):
        """
        匹配banner.product字段，在其自有的tags基础上再打上trojan标签
        :return:
        """
        count = 0
        cursor = self.shodan.find({'status': '200', 'banner.product': self.trojan_tags_reobj})
        for cur in cursor:
            doc = {'ip': cur.get('ip_str'),
                   'inserttime': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time())),
                   'detecttime': cur.get('timestamp')}
            tags = cur.get('tags')
            tags.append('trojan')

            self.ip_tags.update({'ip': cur.get('ip_str')},
                                {'$set': doc,
                                 '$addToSet': {'tags': {'$each': list(tags)}}},
                                upsert=True)
            count += 1

        print '[trojan]banner.product: %d' % count

    def add_all(self):
        """
        调用所有的添加标签函数
        :return:
        """
        self.add_tags_shodan()
        self.add_tags_iot()
        self.add_tags_trojan()


if __name__ == '__main__':
    addtags = AddTags()
    addtags.add_all()


