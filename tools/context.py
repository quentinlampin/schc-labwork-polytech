from json import dumps
from typing import Dict, List
from dataclasses import dataclass

from texttable import Texttable

from microschc.rfc8724 import RuleDescriptor, PacketDescriptor, DirectionIndicator, MatchMapping
from microschc.binary import Buffer
from microschc.rfc8724extras import Context
from microschc.manager import ContextManager, MatchStrategy
from microschc.rfc8724 import CompressionDecompressionAction as CDA
from microschc.rfc8724 import MatchingOperator as MO

from tools.template import Template



@dataclass
class RuleStatistics:
    rule_descriptor: RuleDescriptor
    template: int
    hits: int
    compressible: int
    incompressible: int
    residue: int

    def __init__(self, rule_descriptor: RuleDescriptor):
        self.rule_descriptor = rule_descriptor
        self.template = -1
        self.hits = 0
        self.misses = {rfd.id: 0 for rfd in rule_descriptor.field_descriptors}
        self.compressible = 0
        self.incompressible = 0
        self.residue = 0
    
    @property
    def compression_factor(self) -> float:
        if self.residue == 0:
            return 0.
        return (self.compressible + self.incompressible)/self.residue
    
    @property
    def compression_factor_on_compressible(self):
        if self.residue-self.incompressible == 0:
            return 0.
        return (self.compressible)/(self.residue-self.incompressible)
    
    def __repr__(self) -> str:
        return f"[{self.rule_descriptor.id}] hits:{self.hits} CF:{self.compression_factor}  CFOC:{self.compression_factor_on_compressible} compressible/incompressible: {self.compressible}/{self.incompressible} residue: {self.residue} "


@dataclass
class ContextStatistics:
    context: Context
    templates : List[Template]
    dataset_statistics: Dict[str, float]
    rule_statistics: Dict[int, RuleStatistics]
    

    def __init__(self, context: Context, templates: List[Template]):
        self.context = context
        self.templates = templates


        self.dataset_statistics = {
            'packets': 0.,
            'size': 0.,
            'compressible': 0.,
            'incompressible': 0.
        }
        self.rule_statistics = {}

        template_hashes: List[int]  = []

        for template in templates:
            template_hash = hash(''.join([fd.id for fd in template.fields]))
            template_hashes.append(template_hash)

        for rule_descriptor in self.context.ruleset:
            template_hash = hash(''.join([fd.id for fd in rule_descriptor.field_descriptors]))
            if template_hash not in template_hashes:
                template_hashes.append(template_hash)

            rule_statistic = RuleStatistics(rule_descriptor=rule_descriptor)
            rule_statistic.template = template_hashes.index(template_hash)
            
            rule_id: int = int.from_bytes(rule_descriptor.id.content, byteorder='big')
            self.rule_statistics[rule_id] = rule_statistic
        self.miss_matches: Dict[int, Buffer] = {}

    @property
    def residue(self) -> int:
        residue: int = sum([rule_statistic.residue for _, rule_statistic in self.rule_statistics.items()])
        return residue

    @property
    def compression_factor(self) -> float:
        residue: int = sum([rule_statistic.residue for _, rule_statistic in self.rule_statistics.items()])
        compressible: int = sum([rule_statistic.compressible for _, rule_statistic in self.rule_statistics.items()])
        incompressible: int = sum([rule_statistic.incompressible for _, rule_statistic in self.rule_statistics.items()])
        if residue == 0:
            return 0.
        return (compressible + incompressible)/residue
    
    @property
    def compression_factor_on_compressible(self) -> float:
        residue: int = sum([rule_statistic.residue for _, rule_statistic in self.rule_statistics.items()])
        compressible: int = sum([rule_statistic.compressible for _, rule_statistic in self.rule_statistics.items()])
        incompressible: int = sum([rule_statistic.incompressible for _, rule_statistic in self.rule_statistics.items()])
        if residue-incompressible == 0:
            return 0.
        return (compressible)/(residue-incompressible)
    
    def __json__(self) -> object:
        json_object: object = {
            'context': self.context.__json__(),
            'dataset': self.dataset_statistics,
            'metrics': {
                'overall': {
                    'compression_factor': self.compression_factor,
                    'compression_factor_on_compressible': self.compression_factor_on_compressible,
                    'residue': self.residue
                },
                'rules': {
                    #fill in next loop
                }
            }
        }
        for rule_id, statistics in self.rule_statistics.items():
            json_object['metrics']['rules'][rule_id] = {
                'hits': statistics.hits,
                'misses': statistics.misses,
                'compression_factor': statistics.compression_factor,
                'compression_factor_on_compressible': statistics.compression_factor_on_compressible,
                'compressible': statistics.compressible,
                'incompressible': statistics.incompressible,
                'residue': statistics.residue
            }
        return json_object
    
    def json(self):
        jsonisable = self.__json__()
        json_str: str = dumps(jsonisable, indent=2)
        return json_str

def evaluate(context: Context, templates: List[Template], packets: List[Buffer], match_strategy: MatchStrategy):
    context_manager: ContextManager = ContextManager(context=context)
    context_statistics = ContextStatistics(context=context, templates=templates)

    for i, packet in enumerate(packets):
        packet_descriptor: PacketDescriptor = context_manager.parser.parse(packet)
        packet_descriptor.direction = DirectionIndicator.UP
        context_statistics.dataset_statistics['packets'] += 1
        context_statistics.dataset_statistics['compressible'] += sum([field.value.length for field in packet_descriptor.fields])
        context_statistics.dataset_statistics['incompressible'] += packet_descriptor.payload.length

        compressed_packet:Buffer = context_manager.compress(packet=packet, match_strategy=match_strategy)
        rule_descriptor: RuleDescriptor = context_manager.ruler.match_schc_packet(compressed_packet)

        
        # context statistics
        rule_id: int = int.from_bytes(rule_descriptor.id.content, byteorder='big')
        rule_statistic = context_statistics.rule_statistics[rule_id]
        rule_statistic.hits += 1
        rule_statistic.compressible += sum([field.value.length for field in packet_descriptor.fields])
        rule_statistic.incompressible += packet_descriptor.payload.length
        rule_statistic.residue += compressed_packet.length


    context_statistics.dataset_statistics['size'] = context_statistics.dataset_statistics['compressible'] + context_statistics.dataset_statistics['incompressible']
    return context_statistics


def context_statistics_as_ascii_table(context_statistics, max_width:int=256):
    """
    returns a multiline string representation of a rule to print to the console.
    """
    overall_hits:int = 0 
    overall_residue:int = context_statistics.residue
    overall_size: int = context_statistics.dataset_statistics['size']
    overall_compression_factor: float = context_statistics.compression_factor
    overall_compression_factor_on_compressible: float = context_statistics.compression_factor_on_compressible
    overall_compressible: int = context_statistics.dataset_statistics['compressible']
    overall_incompressible: int = context_statistics.dataset_statistics['incompressible']

    rule_statistics_sorted = dict(sorted(context_statistics.rule_statistics.items(), key=lambda it: it[1].template))
    rules_table = Texttable(max_width=max_width)
    misses_tables = []
    misses_table_titles = []

    rules_rows = [
        ['ID', 'template', 'hits', 'CF', 'CFOC', 'compressible', 'incompressible', 'total', 'residue']
    ]

    
    for id, rs in rule_statistics_sorted.items():
        overall_hits += rs.hits
        rule_row = [f"{id}", f"{rs.template}", f"{rs.hits}", f"{rs.compression_factor}", f"{rs.compression_factor_on_compressible}", f"{rs.compressible}", f"{rs.incompressible}", f"{rs.compressible+rs.incompressible}", f"{rs.residue}"]
        rules_rows.append(rule_row)
        
        misses_table_title: str = f'Template {rs.template} Rule {id}'
        misses_table_titles.append(misses_table_title)

        misses_table: Texttable = Texttable(max_width=max_width)
        misses_rows = [
            ['FID', 'LEN', 'FD', 'MO/CDA', 'TV', 'MISSES']
        ]
        for (fid, misses), rfd in zip(rs.misses.items(), rs.rule_descriptor.field_descriptors):
            if rfd.compression_decompression_action in [CDA.NOT_SENT, CDA.LSB]:
                row = [f"{rfd.id}", f"{rfd.length}", f"{rfd.direction}", f"{rfd.matching_operator}/{'LSB' if rfd.compression_decompression_action == CDA.LSB else 'NOT SENT'}",  f"{rfd.target_value}", f"{misses}"]
            elif rfd.compression_decompression_action is CDA.MAPPING_SENT:
                target_value_str = ""
                target_value: MatchMapping = rfd.target_value
                for k,v in target_value.reverse.items():
                    target_value_str += f"{k}: {v}\n"
                row = [f"{rfd.id}", f"{rfd.length}", f"{rfd.direction}", f"{rfd.matching_operator}/{rfd.compression_decompression_action}",  target_value_str, f"{misses}"]
            elif rfd.compression_decompression_action in {CDA.VALUE_SENT, CDA.COMPUTE}:
                row = [f"{rfd.id}", f"{rfd.length}", f"{rfd.direction}", f"{rfd.matching_operator}/{rfd.compression_decompression_action}",  "", f"{misses}"]


            misses_rows.append(row)
        
        misses_table.add_rows(misses_rows)
        misses_tables.append(misses_table)

    row = ['all', overall_hits, overall_compression_factor, overall_compression_factor_on_compressible, overall_compressible, overall_incompressible, overall_size, overall_residue, 'N/A']
    rules_rows.append(row)
    rules_table.add_rows(
        rows=rules_rows
    )

    rules_table_str = rules_table.draw()
    
    return rules_table_str