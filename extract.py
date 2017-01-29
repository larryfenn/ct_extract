# Python 3
# TODO: add error and consistency checks
# (verify number and size of files is correct)

from binascii import hexlify
from zlib import decompress, decompressobj
from bz2 import BZ2Decompressor
from os import makedirs, listdir, path
import re


def construct_header(array, head):
    header = b''
    for offset in range(6):
        index = (head + offset) % 6
        header += array[index]
    return header

def swap_bytes(first, second):
    return second + first

def collapse(bytes):
    sum = b''
    for byte in bytes:
        sum += byte
    return sum

def parse_chunk(handle, n_bytes):
    bytes = n_bytes * [b'']
    for i in range(n_bytes):
        bytes[i] = hexlify(f.read(1))
    bytes.reverse()
    return int(collapse(bytes).decode('ascii'), 16)

def cleanup_desc(raw):
    raw_path = re.split(b'\x00+', desc_raw)
    return raw_path[0].decode('ascii')


global_header = b'777767542948' # Clickteam installer data header

for file in listdir():
    if file.endswith('.exe'):
        try:
            root = file.split('.')[0]
            with open("{0}.exe".format(root), 'rb') as f:
                seeking_header = True
                last_six_bytes = 6 * [b'']
                head = 0
                byte = 'dummy'
                # step 1: seek to header location
                while seeking_header:
                    byte = f.read(1)
                    last_six_bytes[head] = hexlify(byte)
                    head = (head + 1) % 6
                    header = construct_header(last_six_bytes, head)
                    seeking_header = global_header != header
                # step 2: block enumeration and ID
                blocks = dict()
                block_id = swap_bytes(hexlify(f.read(1)), hexlify(f.read(1)))
                while block_id != b'7f7f': # 7f7f is the last block
                    # next two bytes are padding and unused
                    f.read(2)
                    # next four bytes are size of the data stream in bytes
                    # the data stream always starts with 5 bytes of metadata
                    size = parse_chunk(f, 4) - 5
                    # first four bytes of metadata: uncompressed size
                    uncomp_size = parse_chunk(f, 4)
                    # compression flag: 0 - uncompressed, 1 - zlib, 2 - bzip
                    compress_flag = parse_chunk(f, 1)
                    data = f.read(size)
                    blocks[block_id] = {'flag': compress_flag,
                                        'size': uncomp_size,
                                        'data': data}
                    block_id = swap_bytes(hexlify(f.read(1)),
                                          hexlify(f.read(1)))
                # step 3: parse the file metadata block (id 143a)
                file_metadata = dict()
                desc_stream = decompress(blocks[b'143a']['data'])
                n_files = int(hexlify(desc_stream[:1]), 16)
                desc_stream = desc_stream[4:]
                # there's a lot of metadata in file metadata block whose
                # purpose is unknown- we don't need it, so we ignore it
                for i in range(n_files):
                    frame_size = int(hexlify(swap_bytes(desc_stream[:1],
                                                        desc_stream[1:2])), 16)
                    desc_stream = desc_stream[2:]
                    frame = desc_stream[:frame_size-2]
                    desc_raw = frame[62:]
                    file_metadata[i] = cleanup_desc(desc_raw)
                    desc_stream = desc_stream[frame_size - 2:]
                # step 4: decompress block 7f7f using file metadata
                f.read(10)
                rest = f.read()
                index = 0
                has_next = True
                while(has_next):
                    flag = rest[:1]
                    rest = rest[1:]
                    if flag == b'\x01':
                        expander = decompressobj()
                    if flag == b'\x02':
                        expander = BZ2Decompressor()
                    datafile = expander.decompress(rest)
                    rest = expander.unused_data
                    has_next = expander.unused_data != b''
                    filename = "{0}\\{1}".format(root, file_metadata[index])

                    filepath = '\\'.join(filename.split('\\')[:-1])
                    if not path.exists(filepath):
                        makedirs(filepath)

                    with open(filename, 'wb') as f:
                        f.write(datafile)
                    index += 1
        except:
            pass # TODO: write exceptions out
