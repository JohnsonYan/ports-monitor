# encoding=utf-8

import pymongo

class Utils_mongodb(object):
    """
    工具类
    """

    def read_file(self, filepath):
        """
        通过可迭代的方式读取文件
        缓冲区大小：1024
        Args:
            filepath: 文件路径
        """
        block_size = 1024
        with open(str(filepath), 'rb') as f:
            while True:
                block = f.read(block_size)
                if block:
                    yield block
                else:
                    return

    def __init__(self):
        pass

def main():
    tools = Tools()
    data = tools.read_file('utils_mongodb.py')
    for d in data:
        print d

if __name__ == '__main__':
    main()
