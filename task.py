# encoding=utf-8
import datetime
import time

import libmasscan.masscan as masscan
import libmasscan.output_masscan_ip as output_masscan_ip


def task():
    """
    调度函数，shodan-ip -> input.txt -> masscan 扫描 input.txt
    :return:
    """
    print '[task Running...]'
    while True:
        try:
            now = datetime.datetime.now()
            # 每小时检查一次是否可以开始任务
            if now.hour == 15:
                output_masscan_ip.output()
                scan = masscan.Masscan()
                scan.run()
            time.sleep(60*60)
        except Exception as msg:
            print msg


if __name__ == '__main__':
    task()
