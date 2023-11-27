from typing import List

from pcapng import FileScanner
from pcapng.blocks import EnhancedPacket, Block

from microschc.binary import Buffer


ETHERNET_HEADER_LENGTH_BYTES = 14

def packet_filter(block: Block) -> bool:
    return isinstance(block, EnhancedPacket)

def packets_list(file: str, header_offset: int = ETHERNET_HEADER_LENGTH_BYTES) -> List[Buffer]:
    """returns packets from a PCAPng file.

    Args:
        file (str): path of the PCAPng file
        header_offset (int, optional): numbers of bytes to strip at the beginning of the packets. Defaults to ETHERNET_HEADER_LENGTH_BYTES.

    Returns:
        List[Buffer]: list of packets, stripped from the `header_offset` first bytes.
    """
    with open(file, 'rb') as fp:
            # retrieve all context packets
            scanner: FileScanner = FileScanner(fp) 
            packets:List[Buffer] = [
                Buffer(
                    content=p.packet_data[header_offset:],
                    length=(p.packet_len-header_offset)*8
                ) for p in filter(packet_filter, scanner)
            ]
    return packets