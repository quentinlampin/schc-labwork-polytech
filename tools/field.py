from typing import List, Tuple, Set
from microschc.binary import Buffer
from texttable import Texttable

def fields_as_asciitable(fields: List[Tuple[int, str, Set[Buffer]]], max_width:int=256):
    """generate a string representation of a list of fields

    Args:
        fields (List[Tuple[str, Set[Buffer]]): list of fields with values
        max_width (int, optional): max width of the table in characters. Defaults to 256.
    """    
    table = Texttable(max_width=max_width)
    rows = [
        ['field ID', 'value']
    ]
    for field_tuple in fields:
        row = [f"{field_tuple[0]} - {field_tuple[1]}", f"{field_tuple[2]}"] if len(field_tuple[2]) < 4 else [f"{field_tuple[0]} - {field_tuple[1]}", f"{list(field_tuple[2])[0:8]} ... ({len(field_tuple[2])})"]
        rows.append(row)
    table.add_rows(
        rows=rows
    )
    return table.draw()