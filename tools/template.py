from typing import List, Set, Union, Dict
from microschc.rfc8724 import FieldDescriptor, PacketDescriptor, RuleDescriptor, RuleFieldDescriptor
from microschc.binary.buffer import Buffer
from microschc.parser.parser import PacketParser, PacketDescriptor, DirectionIndicator

from texttable import Texttable

import random

class Template:
    """
    a list of fields shared by a set of of packets
    """
    def __init__(self, fields: List[FieldDescriptor]):
        self.fields: List[FieldDescriptor] = fields
        self.packets: Set[PacketDescriptor] = set()

    def __eq__(self, other):
        return hash(self) == hash(other)

    def __hash__(self) -> int:
        return hash("|".join([f.id for f in self.fields]))
    
    def __repr__(self):
        fields: str = "|".join(f.id for f in self.fields)
        return f"{fields}|"
    
    def random_sample(self, items: Union[int, float]):
        if isinstance(items, int):
            k = items
        elif isinstance(items, float):
            k = int(items * len(self.packets))
        else:
            raise ValueError()
        packets: Set[PacketDescriptor] = set(random.sample(list(self.packets), k=k))
                                             
        new_template: Template = Template(self.fields)
        new_template.packets = packets
        return new_template

    def __sub__(self, another):
        if isinstance(another, Template):
            packets_to_remove = another.packets
            
        elif isinstance(another, list):
            packets_to_remove = another
        else:
            raise ValueError()
        
        packets: Set[PacketDescriptor] = self.packets - packets_to_remove
        new_template: Template = Template(self.fields)
        new_template.packets = packets
        return new_template

        

def find_templates(packets:List[Buffer], parser: PacketParser) -> List[Template]:
    templates_dict: Dict[int, Template] = {}
    templates: List[Template] = []

    for packet in packets:
        packet_descriptor: PacketDescriptor = parser.parse(packet)
        fields: List[FieldDescriptor] = packet_descriptor.fields
        template: Template = Template(fields=fields)

        if hash(template) in templates_dict.keys():
            template = templates_dict[hash(template)]
        else:
            templates_dict[hash(template)] = template
        templates_dict[hash(template)].packets.add(packet_descriptor)

    for _, template in templates_dict.items():
        templates.append(template)
    templates = sorted(templates, key= lambda t: len(t.packets), reverse=True)

    return templates

def template_as_asciitable(template: Template, max_width:int=256) -> str:
    """
    returns a multiline string representation of a template to print to the console.
    """
    table = Texttable(max_width=max_width)
    rows = [
        ['field ID', 'length']
    ]
    for fd in template.fields:
        row = [f"{fd.id.value}", f"{fd.value.length}"]
        
        rows.append(row)
    table.add_rows(
        rows=rows
    )
    return table.draw()