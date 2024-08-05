import argparse
import requests
import struct

class ParsingError(Exception): pass

class DataBlock(object):
    def __init__(self, data):
        super(DataBlock, self).__init__()
        self.data = data
        self.pos = 0

    def offset_read(self, length, offset=None):
        if not offset:
            offset_position = self.pos
        else:
            offset_position = offset

        if len(self.data) < offset_position + length:
            raise ParsingError("Offset+Length > len(self.data)")

        if not offset:
            self.pos += length

        return self.data[offset_position:offset_position + length]

    def skip(self, length):
        self.pos += length

    def read_filename(self):
        length, = struct.unpack_from(">I", self.offset_read(4))
        filename = self.offset_read(2 * length).decode("utf-16be")
        structure_id, = struct.unpack_from(">I", self.offset_read(4))
        structure_type, = struct.unpack_from(">4s", self.offset_read(4))
        structure_type = structure_type.decode()
        skip = -1
        while skip < 0:
            if structure_type == "bool":
                skip = 1
            elif structure_type in ("type", "long", "shor", "fwsw", "fwvh", "icvt", "lsvt", "vSrn", "vstl"):
                skip = 4
            elif structure_type in ("comp", "dutc", "icgo", "icsp", "logS", "lg1S", "lssp", "modD", "moDD", "phyS", "ph1S"):
                skip = 8
            elif structure_type == "blob":
                blen, = struct.unpack_from(">I", self.offset_read(4))
                skip = blen
            elif structure_type in ("ustr", "cmmt", "extn", "GRP0"):
                blen, = struct.unpack_from(">I", self.offset_read(4))
                skip = 2 * blen
            elif structure_type == "BKGD":
                skip = 12
            elif structure_type in ("ICVO", "LSVO", "dscl"):
                skip = 1
            elif structure_type == "Iloc":
                skip = 16
            elif structure_type == "dilc":
                skip = 32
            elif structure_type == "lsvo":
                skip = 76
            elif structure_type == "icvo":
                pass
            elif structure_type == "info":
                pass
            else:
                pass

            if skip <= 0:
                self.skip(-1 * 2 * 0x4)
                filename += self.offset_read(0x2).decode("utf-16be")
                structure_id, = struct.unpack_from(">I", self.offset_read(4))
                structure_type, = struct.unpack_from(">4s", self.offset_read(4))
                structure_type = structure_type.decode()
                future_structure_type = struct.unpack_from(">4s", self.offset_read(4, offset=self.pos))
                if structure_type != "blob" and future_structure_type != "blob":
                    structure_type = ""

        self.skip(skip)
        return filename

class DS_Store(DataBlock):
    def __init__(self, data):
        super(DS_Store, self).__init__(data)
        self.root = self.__read_header()
        self.offsets = self.__read_offsets()
        self.toc = self.__read_TOC()
        self.freeList = self.__read_freelist()

    def __read_header(self):
        if len(self.data) < 36:
            raise ParsingError("Length of data is too short!")

        magic1, magic2 = struct.unpack_from(">II", self.offset_read(2*4))
        if not magic1 == 0x1 and not magic2 == 0x42756431:
            raise ParsingError("Magic byte 1 does not match!")

        offset, size, offset2 = struct.unpack_from(">III", self.offset_read(3*4))
        if not offset == offset2:
            raise ParsingError("Offsets do not match!")
        self.skip(4*4)

        return DataBlock(self.offset_read(size, offset+4))

    def __read_offsets(self):
        start_pos = self.root.pos
        count, = struct.unpack_from(">I", self.root.offset_read(4))
        self.root.skip(4)

        offsets = []
        for i in range(count):
            address, = struct.unpack_from(">I", self.root.offset_read(4))
            if address == 0:
                continue
            offsets.append(address)

        section_end = start_pos + (count // 256 + 1) * 256 * 4 - count*4
        self.root.skip(section_end)
        return offsets

    def __read_TOC(self):
        count, = struct.unpack_from(">I", self.root.offset_read(4))
        toc = {}
        for i in range(count):
            toc_len, = struct.unpack_from(">b", self.root.offset_read(1))
            toc_name, = struct.unpack_from(">{}s".format(toc_len), self.root.offset_read(toc_len))
            block_id, = struct.unpack_from(">I", self.root.offset_read(4))
            toc[toc_name.decode()] = block_id

        return toc

    def __read_freelist(self):
        freelist = {}
        for i in range(32):
            freelist[2**i] = []
            blkcount, = struct.unpack_from(">I", self.root.offset_read(4))
            for j in range(blkcount):
                free_offset, = struct.unpack_from(">I", self.root.offset_read(4))
                freelist[2**i].append(free_offset)

        return freelist

    def __block_by_id(self, block_id):
        if len(self.offsets) < block_id:
            raise ParsingError("BlockID out of range!")

        addr = self.offsets[block_id]
        offset = (int(addr) >> 0x5 << 0x5)
        size = 1 << (int(addr) & 0x1f)
        return DataBlock(self.offset_read(size, offset + 0x4))

    def traverse_root(self):
        root = self.__block_by_id(self.toc['DSDB'])
        root_id, = struct.unpack(">I", root.offset_read(4))
        internal_block_count, = struct.unpack(">I", root.offset_read(4))
        record_count, = struct.unpack(">I", root.offset_read(4))
        block_count, = struct.unpack(">I", root.offset_read(4))
        unknown, = struct.unpack(">I", root.offset_read(4))

        return self.traverse(root_id)

    def traverse(self, block_id):
        node = self.__block_by_id(block_id)
        next_pointer, = struct.unpack(">I", node.offset_read(4))
        count, = struct.unpack(">I", node.offset_read(4))

        filenames = set()  # Use a set to store unique filenames
        if next_pointer > 0:
            for i in range(0, count, 1):
                next_id, = struct.unpack(">I", node.offset_read(4))
                files = self.traverse(next_id)
                filenames.update(files)
                filename = node.read_filename()
                filenames.add(filename)
            files = self.traverse(next_pointer)
            filenames.update(files)
        else:
            for i in range(0, count, 1):
                f = node.read_filename()
                filenames.add(f)

        return filenames

def fetch_ds_store(url):
    try:
        response = requests.get(url)
        response.raise_for_status()
        return response.content
    except requests.RequestException as e:
        print(f"Error fetching .DS_Store file: {e}")
        return None

def main():
    parser = argparse.ArgumentParser(description="Extract filenames from a .DS_Store file.")
    parser.add_argument('-u', '--url', type=str, required=True, help='URL of the .DS_Store file')
    args = parser.parse_args()

    data = fetch_ds_store(args.url)
    if data:
        ds_store = DS_Store(data)
        filenames = ds_store.traverse_root()
        print("Unique filenames extracted from .DS_Store:")
        for filename in sorted(filenames):  # Sort for consistent ordering
            print(filename)

if __name__ == "__main__":
    main()
