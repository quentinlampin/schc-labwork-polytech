from texttable import Texttable

from microschc.rfc8724 import PacketDescriptor
from microschc.binary import Buffer

from typing import List, Set, Tuple

def packet_descriptor_as_asciitable(packet_descriptor: PacketDescriptor, max_width:int=256) -> str:
    """generate a string representation of a packet descriptor as asciitable

    Args:
        packet_descriptor (PacketDescriptor): packet descriptor to represent as ASCII table
        max_width (int, optional): max width of the table in characters. Defaults to 256.

    Returns:
        str: the string representation of the packet descriptor
    """    
    table = Texttable(max_width=max_width)
    rows = [
        ['field ID', 'value']
    ]
    for fd in packet_descriptor.fields:
        row = [f"{fd.id.value}", f"{fd.value}"]
        rows.append(row)
    table.add_rows(
        rows=rows
    )
    return table.draw()
