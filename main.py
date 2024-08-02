from flirt_process import FLIRTProcess
from repair_symbols import RepairSymbols
import logging
import os

logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)

if __name__ == "__main__":
    sig_dir = './sig'
    binary = './bin/test'
    dest = './bin/test_repair'
    
    # 解析sig_dir中的sig文件，一次对binary进行match
    # 选择最佳match的sig文件，输出match到的函数地址和函数名
    fp = FLIRTProcess(sig_dir, binary)
    symbols = fp.run()
    if symbols is None:
        log.error('identify symbols failed!')
        
    for key in symbols.keys():
        log.info("0x%d %s", key, symbols[key])
        
    # 借助radar2工具把match到的函数符号打入binary
    rs = RepairSymbols(binary, dest, symbols)
    if rs.run() < 0:
        log.error('repair symbols failed!')