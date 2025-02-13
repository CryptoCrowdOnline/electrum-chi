# Electrum - lightweight Bitcoin client
# Copyright (C) 2012 thomasv@ecdsa.org
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation files
# (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge,
# publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
import os
import threading
import time
from typing import Optional, Dict, Mapping, Sequence

from . import util
from .bitcoin import hash_encode, int_to_hex, rev_hex
from .crypto import sha256d
from . import constants
from .util import bfh, bh2u
from .simple_config import SimpleConfig
from .logging import get_logger, Logger

from . import auxpow
from . import difficulty
from . import powdata

_logger = get_logger(__name__)

PURE_HEADER_SIZE = 80  # bytes
DISK_HEADER_SIZE = PURE_HEADER_SIZE + 5 + 32
MAX_TARGET = 0x00000000FFFF0000000000000000000000000000000000000000000000000000


class MissingHeader(Exception):
    pass

class InvalidHeader(Exception):
    pass

def serialize_pure_header(header_dict: dict) -> str:
    s = int_to_hex(header_dict['version'], 4) \
        + rev_hex(header_dict['prev_block_hash']) \
        + rev_hex(header_dict['merkle_root']) \
        + int_to_hex(int(header_dict['timestamp']), 4) \
        + int_to_hex(int(header_dict['bits']), 4) \
        + int_to_hex(int(header_dict['nonce']), 4)
    return s

def serialize_disk_header(header_dict: dict) -> str:
    s = serialize_pure_header(header_dict)
    s += powdata.serialize_base(header_dict['powdata'])
    s += ("%064x" % header_dict["chainwork"])
    return s

def deserialize_pure_header(s: bytes, height: int) -> dict:
    if not s:
        raise InvalidHeader('Invalid header: {}'.format(s))
    if len(s) != PURE_HEADER_SIZE:
        raise InvalidHeader('Invalid header length: {}'.format(len(s)))
    hex_to_int = lambda s: int.from_bytes(s, byteorder='little')
    h = {}
    h['version'] = hex_to_int(s[0:4])
    h['prev_block_hash'] = hash_encode(s[4:36])
    h['merkle_root'] = hash_encode(s[36:68])
    h['timestamp'] = hex_to_int(s[68:72])
    h['bits'] = hex_to_int(s[72:76])
    h['nonce'] = hex_to_int(s[76:80])
    h['block_height'] = height
    return h

def deserialize_disk_header(s: bytes, height: int) -> dict:
    pure_header_bytes = s[:PURE_HEADER_SIZE]
    h = deserialize_pure_header(s[:PURE_HEADER_SIZE], height)

    h['powdata'], start_position = powdata.deserialize_base(s, start_position=PURE_HEADER_SIZE)

    work_bytes = s[start_position : start_position + 32]
    if len (work_bytes) < 32:
        raise Exception(f'Invalid header length: {original_len}')
    # Since we serialise chainwork to hex by using %064x, we get a big endian
    # byte order for the data.
    h["chainwork"] = int.from_bytes(work_bytes, byteorder="big")
    start_position += 32

    if start_position != len(s):
        raise Exception('Invalid header length: {}'.format(len(s)))
    return h

def deserialize_full_header(s: bytes, height: int, expect_trailing_data=False, start_position=0):
    """Deserialises a full block header which may include AuxPoW.

    If expect_trailing_data is true, then we allow trailing data and return
    the end position in the byte array alongside the header dict.  Otherwise
    an error is raised if there is trailing, unconsumed data."""

    original_start = start_position

    pure_header_bytes = s[start_position : start_position + PURE_HEADER_SIZE]
    h = deserialize_pure_header(pure_header_bytes, height)
    start_position += PURE_HEADER_SIZE

    # We use height=None for cases where we want to disable truncated headers
    # in tests.  Also, when there are no checkpoints at all, then we do not
    # want the genesis block to be truncated.
    if height == 0 and constants.net.CHECKPOINTS == []:
        height = None
    if height is not None and height <= constants.net.max_checkpoint():
        h['powdata'], start_position = powdata.deserialize_base(s, start_position=start_position)
    else:
        h['powdata'], start_position = powdata.deserialize(s, start_position=start_position)

    if expect_trailing_data:
        return h, start_position

    if start_position != len(s):
        raise Exception('Invalid header length: {}'.format(len(s) - original_start))
    return h

def hash_header(header: dict) -> str:
    if header is None:
        return '0' * 64
    if header.get('prev_block_hash') is None:
        header['prev_block_hash'] = '00'*32
    return hash_raw_header(serialize_pure_header(header))


def hash_raw_header(header: str) -> str:
    return hash_encode(sha256d(bfh(header)))


# key: blockhash hex at forkpoint
# the chain at some key is the best chain that includes the given hash
blockchains = {}  # type: Dict[str, Blockchain]
blockchains_lock = threading.RLock()


def read_blockchains(config: 'SimpleConfig'):
    best_chain = Blockchain(config=config,
                            forkpoint=0,
                            parent=None,
                            forkpoint_hash=constants.net.GENESIS,
                            prev_hash=None)
    blockchains[constants.net.GENESIS] = best_chain
    # consistency checks
    if best_chain.height() > constants.net.max_checkpoint():
        header_after_cp = best_chain.read_header(constants.net.max_checkpoint()+1)
        if not header_after_cp or not best_chain.can_connect(header_after_cp, check_height=False, skip_auxpow=True):
            _logger.info("[blockchain] deleting best chain. cannot connect header after last cp to last cp.")
            os.unlink(best_chain.path())
            best_chain.update_size()
    # forks
    fdir = os.path.join(util.get_headers_dir(config), 'forks')
    util.make_dir(fdir)
    # files are named as: fork2_{forkpoint}_{prev_hash}_{first_hash}
    l = filter(lambda x: x.startswith('fork2_') and '.' not in x, os.listdir(fdir))
    l = sorted(l, key=lambda x: int(x.split('_')[1]))  # sort by forkpoint

    def delete_chain(filename, reason):
        _logger.info(f"[blockchain] deleting chain {filename}: {reason}")
        os.unlink(os.path.join(fdir, filename))

    def instantiate_chain(filename):
        __, forkpoint, prev_hash, first_hash = filename.split('_')
        forkpoint = int(forkpoint)
        prev_hash = (64-len(prev_hash)) * "0" + prev_hash  # left-pad with zeroes
        first_hash = (64-len(first_hash)) * "0" + first_hash
        # forks below the max checkpoint are not allowed
        if forkpoint <= constants.net.max_checkpoint():
            delete_chain(filename, "deleting fork below max checkpoint")
            return
        # find parent (sorting by forkpoint guarantees it's already instantiated)
        for parent in blockchains.values():
            if parent.check_hash(forkpoint - 1, prev_hash):
                break
        else:
            delete_chain(filename, "cannot find parent for chain")
            return
        b = Blockchain(config=config,
                       forkpoint=forkpoint,
                       parent=parent,
                       forkpoint_hash=first_hash,
                       prev_hash=prev_hash)
        # consistency checks
        h = b.read_header(b.forkpoint)
        if first_hash != hash_header(h):
            delete_chain(filename, "incorrect first hash for chain")
            return
        if not b.parent.can_connect(h, check_height=False):
            delete_chain(filename, "cannot connect chain to parent")
            return
        chain_id = b.get_id()
        assert first_hash == chain_id, (first_hash, chain_id)
        blockchains[chain_id] = b

    for filename in l:
        instantiate_chain(filename)


def get_best_chain() -> 'Blockchain':
    return blockchains[constants.net.GENESIS]


def init_headers_file_for_best_chain():
    b = get_best_chain()
    filename = b.path()
    length = DISK_HEADER_SIZE * len(constants.net.CHECKPOINTS) * 2016
    if not os.path.exists(filename) or os.path.getsize(filename) < length:
        with open(filename, 'wb') as f:
            if length > 0:
                f.seek(length - 1)
                f.write(b'\x00')
        util.ensure_sparse_file(filename)
    with b.lock:
        b.update_size()


class Blockchain(Logger):
    """
    Manages blockchain headers and their verification
    """

    def __init__(self, config: SimpleConfig, forkpoint: int, parent: Optional['Blockchain'],
                 forkpoint_hash: str, prev_hash: Optional[str]):
        assert isinstance(forkpoint_hash, str) and len(forkpoint_hash) == 64, forkpoint_hash
        assert (prev_hash is None) or (isinstance(prev_hash, str) and len(prev_hash) == 64), prev_hash
        # assert (parent is None) == (forkpoint == 0)
        if 0 < forkpoint <= constants.net.max_checkpoint():
            raise Exception(f"cannot fork below max checkpoint. forkpoint: {forkpoint}")
        Logger.__init__(self)
        self.config = config
        self.forkpoint = forkpoint  # height of first header
        self.parent = parent
        self._forkpoint_hash = forkpoint_hash  # blockhash at forkpoint. "first hash"
        self._prev_hash = prev_hash  # blockhash immediately before forkpoint
        self.lock = threading.RLock()
        self.update_size()

    def with_lock(func):
        def func_wrapper(self, *args, **kwargs):
            with self.lock:
                return func(self, *args, **kwargs)
        return func_wrapper

    @property
    def checkpoints(self):
        return constants.net.CHECKPOINTS

    def get_max_child(self) -> Optional[int]:
        children = self.get_direct_children()
        return max([x.forkpoint for x in children]) if children else None

    def get_max_forkpoint(self) -> int:
        """Returns the max height where there is a fork
        related to this chain.
        """
        mc = self.get_max_child()
        return mc if mc is not None else self.forkpoint

    def get_direct_children(self) -> Sequence['Blockchain']:
        with blockchains_lock:
            return list(filter(lambda y: y.parent==self, blockchains.values()))

    def get_parent_heights(self) -> Mapping['Blockchain', int]:
        """Returns map: (parent chain -> height of last common block)"""
        with blockchains_lock:
            result = {self: self.height()}
            chain = self
            while True:
                parent = chain.parent
                if parent is None: break
                result[parent] = chain.forkpoint - 1
                chain = parent
            return result

    def get_height_of_last_common_block_with_chain(self, other_chain: 'Blockchain') -> int:
        last_common_block_height = 0
        our_parents = self.get_parent_heights()
        their_parents = other_chain.get_parent_heights()
        for chain in our_parents:
            if chain in their_parents:
                h = min(our_parents[chain], their_parents[chain])
                last_common_block_height = max(last_common_block_height, h)
        return last_common_block_height

    @with_lock
    def get_branch_size(self) -> int:
        return self.height() - self.get_max_forkpoint() + 1

    def get_name(self) -> str:
        return self.get_hash(self.get_max_forkpoint()).lstrip('0')[0:10]

    def check_header(self, header: dict) -> bool:
        header_hash = hash_header(header)
        height = header.get('block_height')
        return self.check_hash(height, header_hash)

    def check_hash(self, height: int, header_hash: str) -> bool:
        """Returns whether the hash of the block at given height
        is the given hash.
        """
        assert isinstance(header_hash, str) and len(header_hash) == 64, header_hash  # hex
        try:
            return header_hash == self.get_hash(height)
        except Exception:
            return False

    def fork(parent, header: dict) -> 'Blockchain':
        if not parent.can_connect(header, check_height=False):
            raise Exception("forking header does not connect to parent chain")
        forkpoint = header.get('block_height')
        self = Blockchain(config=parent.config,
                          forkpoint=forkpoint,
                          parent=parent,
                          forkpoint_hash=hash_header(header),
                          prev_hash=parent.get_hash(forkpoint-1))
        self.assert_headers_file_available(parent.path())
        open(self.path(), 'w+').close()
        self.save_header(header)
        # put into global dict. note that in some cases
        # save_header might have already put it there but that's OK
        chain_id = self.get_id()
        with blockchains_lock:
            blockchains[chain_id] = self
        return self

    @with_lock
    def height(self) -> int:
        return self.forkpoint + self.size() - 1

    @with_lock
    def size(self) -> int:
        return self._size

    @with_lock
    def update_size(self) -> None:
        p = self.path()
        self._size = os.path.getsize(p)//DISK_HEADER_SIZE if os.path.exists(p) else 0

    @classmethod
    def verify_header(cls, header: dict, prev_hash: str, target: int, expected_header_hash: str=None, skip_auxpow: bool=False) -> None:
        _hash = hash_header(header)
        if expected_header_hash and expected_header_hash != _hash:
            raise Exception("hash mismatches with expected: {} vs {}".format(expected_header_hash, _hash))
        if prev_hash != header.get('prev_block_hash'):
            raise Exception("prev hash mismatch: %s vs %s" % (prev_hash, header.get('prev_block_hash')))
        if header.get('bits') != 0:
            raise Exception("main header has non-zero bits: %x" % header.get('bits'))
        if constants.net.TESTNET:
            return
        bits = cls.target_to_bits(target)
        if bits != header["powdata"].get('bits'):
            raise Exception("bits mismatch: %s vs %s" % (bits, header["powdata"].get('bits')))

        # Don't verify AuxPoW when covered by a checkpoint
        if header.get('block_height') <= constants.net.max_checkpoint():
            skip_auxpow = True
        if not skip_auxpow:
            powdata.verify(header["powdata"], _hash)

    def verify_chunk(self, index: int, data: bytes) -> bytes:
        stripped = bytearray()
        start_position = 0
        start_height = index * 2016
        prev_hash = self.get_hash(start_height - 1)
        i = 0

        # Keep track of the accumulated chain work.
        work = self.get_chainwork(start_height - 1)

        # Since blocks in the chunk build on top of earlier ones for computing
        # the expected difficulty, we keep a record of those blocks here
        # before they get written into the main file.
        earlier_blocks = {}

        while start_position < len(data):
            height = start_height + i
            try:
                expected_header_hash = self.get_hash(height)
            except MissingHeader:
                expected_header_hash = None

            header, start_position = deserialize_full_header(data, index*2016 + i, expect_trailing_data=True, start_position=start_position)
            target = self.get_expected_target(header, extra_blocks=earlier_blocks)
            self.verify_header(header, prev_hash, target, expected_header_hash)
            prev_hash = hash_header(header)

            work += self.chainwork_of_header(header)
            header["chainwork"] = work
            stripped.extend(bfh(serialize_disk_header(header)))

            earlier_blocks[height] = header
            i = i + 1

        return bytes(stripped)

    @with_lock
    def path(self):
        d = util.get_headers_dir(self.config)
        if self.parent is None:
            filename = 'blockchain_headers'
        else:
            assert self.forkpoint > 0, self.forkpoint
            prev_hash = self._prev_hash.lstrip('0')
            first_hash = self._forkpoint_hash.lstrip('0')
            basename = f'fork2_{self.forkpoint}_{prev_hash}_{first_hash}'
            filename = os.path.join('forks', basename)
        return os.path.join(d, filename)

    @with_lock
    def save_chunk(self, index: int, chunk: bytes):
        assert index >= 0, index
        chunk_within_checkpoint_region = index < len(self.checkpoints)
        # chunks in checkpoint region are the responsibility of the 'main chain'
        if chunk_within_checkpoint_region and self.parent is not None:
            main_chain = get_best_chain()
            main_chain.save_chunk(index, chunk)
            return

        delta_height = (index * 2016 - self.forkpoint)
        delta_bytes = delta_height * DISK_HEADER_SIZE
        # if this chunk contains our forkpoint, only save the part after forkpoint
        # (the part before is the responsibility of the parent)
        if delta_bytes < 0:
            chunk = chunk[-delta_bytes:]
            delta_bytes = 0
        truncate = not chunk_within_checkpoint_region
        self.write(chunk, delta_bytes, truncate)
        self.swap_with_parent()

    def swap_with_parent(self) -> None:
        with self.lock, blockchains_lock:
            # do the swap; possibly multiple ones
            cnt = 0
            while True:
                old_parent = self.parent
                if not self._swap_with_parent():
                    break
                # make sure we are making progress
                cnt += 1
                if cnt > len(blockchains):
                    raise Exception(f'swapping fork with parent too many times: {cnt}')
                # we might have become the parent of some of our former siblings
                for old_sibling in old_parent.get_direct_children():
                    if self.check_hash(old_sibling.forkpoint - 1, old_sibling._prev_hash):
                        old_sibling.parent = self

    def _swap_with_parent(self) -> bool:
        """Check if this chain became stronger than its parent, and swap
        the underlying files if so. The Blockchain instances will keep
        'containing' the same headers, but their ids change and so
        they will be stored in different files."""
        if self.parent is None:
            return False
        if self.parent.get_chainwork() >= self.get_chainwork():
            return False
        self.logger.info(f"swapping {self.forkpoint} {self.parent.forkpoint}")
        parent_branch_size = self.parent.height() - self.forkpoint + 1
        forkpoint = self.forkpoint  # type: Optional[int]
        parent = self.parent  # type: Optional[Blockchain]
        child_old_id = self.get_id()
        parent_old_id = parent.get_id()
        # swap files
        # child takes parent's name
        # parent's new name will be something new (not child's old name)
        self.assert_headers_file_available(self.path())
        child_old_name = self.path()
        with open(self.path(), 'rb') as f:
            my_data = f.read()
        self.assert_headers_file_available(parent.path())
        assert forkpoint > parent.forkpoint, (f"forkpoint of parent chain ({parent.forkpoint}) "
                                              f"should be at lower height than children's ({forkpoint})")
        with open(parent.path(), 'rb') as f:
            f.seek((forkpoint - parent.forkpoint)*DISK_HEADER_SIZE)
            parent_data = f.read(parent_branch_size*DISK_HEADER_SIZE)
        self.write(parent_data, 0)
        parent.write(my_data, (forkpoint - parent.forkpoint)*DISK_HEADER_SIZE)
        # swap parameters
        self.parent, parent.parent = parent.parent, self  # type: Optional[Blockchain], Optional[Blockchain]
        self.forkpoint, parent.forkpoint = parent.forkpoint, self.forkpoint
        self._forkpoint_hash, parent._forkpoint_hash = parent._forkpoint_hash, hash_raw_header(bh2u(parent_data[:PURE_HEADER_SIZE]))
        self._prev_hash, parent._prev_hash = parent._prev_hash, self._prev_hash
        # parent's new name
        os.replace(child_old_name, parent.path())
        self.update_size()
        parent.update_size()
        # update pointers
        blockchains.pop(child_old_id, None)
        blockchains.pop(parent_old_id, None)
        blockchains[self.get_id()] = self
        blockchains[parent.get_id()] = parent
        return True

    def get_id(self) -> str:
        return self._forkpoint_hash

    def assert_headers_file_available(self, path):
        if os.path.exists(path):
            return
        elif not os.path.exists(util.get_headers_dir(self.config)):
            raise FileNotFoundError('Electrum-CHI headers_dir does not exist. Was it deleted while running?')
        else:
            raise FileNotFoundError('Cannot find headers file but headers_dir is there. Should be at {}'.format(path))

    @with_lock
    def write(self, data: bytes, offset: int, truncate: bool=True) -> None:
        filename = self.path()
        self.assert_headers_file_available(filename)
        with open(filename, 'rb+') as f:
            if truncate and offset != self._size * DISK_HEADER_SIZE:
                f.seek(offset)
                f.truncate()
            f.seek(offset)
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        self.update_size()

    @with_lock
    def save_header(self, header: dict) -> None:
        height = header.get('block_height')
        header["chainwork"] = self.get_chainwork(height - 1) + self.chainwork_of_header(header)

        delta = height - self.forkpoint
        data = bfh(serialize_disk_header(header))
        # headers are only _appended_ to the end:
        assert delta == self.size(), (delta, self.size())
        assert len(data) == DISK_HEADER_SIZE
        self.write(data, delta*DISK_HEADER_SIZE)
        self.swap_with_parent()

    @with_lock
    def read_header(self, height: int) -> Optional[dict]:
        if height < 0:
            return
        if height < self.forkpoint:
            return self.parent.read_header(height)
        if height > self.height():
            return
        delta = height - self.forkpoint
        name = self.path()
        self.assert_headers_file_available(name)
        with open(name, 'rb') as f:
            f.seek(delta * DISK_HEADER_SIZE)
            h = f.read(DISK_HEADER_SIZE)
            if len(h) < DISK_HEADER_SIZE:
                raise Exception('Expected to read a full header. This was only {} bytes'.format(len(h)))
        if h == bytes([0])*DISK_HEADER_SIZE:
            return None
        return deserialize_disk_header(h, height)

    def header_at_tip(self) -> Optional[dict]:
        """Return latest header."""
        height = self.height()
        return self.read_header(height)

    def is_tip_stale(self) -> bool:
        STALE_DELAY = 8 * 60 * 60  # in seconds
        header = self.header_at_tip()
        if not header:
            return True
        # note: We check the timestamp only in the latest header.
        #       The Bitcoin consensus has a lot of leeway here:
        #       - needs to be greater than the median of the timestamps of the past 11 blocks, and
        #       - up to at most 2 hours into the future compared to local clock
        #       so there is ~2 hours of leeway in either direction
        if header['timestamp'] + STALE_DELAY < time.time():
            return True
        return False

    def get_hash(self, height: int) -> str:
        def is_height_checkpoint():
            within_cp_range = height <= constants.net.max_checkpoint()
            at_chunk_boundary = (height+1) % 2016 == 0
            return within_cp_range and at_chunk_boundary

        if height == -1:
            return '0000000000000000000000000000000000000000000000000000000000000000'
        elif height == 0:
            return constants.net.GENESIS
        elif is_height_checkpoint():
            index = height // 2016
            d = self.checkpoints[index]
            return d["hash"]
        else:
            header = self.read_header(height)
            if header is None:
                raise MissingHeader(height)
            return hash_header(header)

    def get_expected_target(self, header: dict, extra_blocks={}) -> int:
        """Computes the difficulty target for a header

        Optionally a dictionary of height -> block mappings can be passed.
        In that case, we try to look up blocks for the difficulty computation
        in there before looking into the main data file."""

        if constants.net.TESTNET:
            return 0

        def getter (algo: int, h: int) -> Optional[dict]:
            return self.difficulty_data_for_block (algo, h, extra_blocks)

        return difficulty.get_target(getter, header["powdata"]["algo"], header["block_height"])

    def difficulty_data_for_block(self, algo: int, h: int, extra_blocks={}) -> Optional[dict]:
        """
        Returns the data that we need for difficulty retargeting (bits,
        height and timestamp) of the last block with height <=h and the
        given algorithm.  May return None if there is no such block.

        If extra_blocks is set, we use it to look up block headers (by height)
        before looking into the main blockchain.
        """

        # This would be well-suited for recursion.  Unfortunately, Python does
        # not optimise tail calls, and hence we need to use a loop or run the
        # risk of hitting the recursion limit.
        while True:
            if h < 0:
                return None

            header = None
            if h in extra_blocks:
                header = extra_blocks[h]
            else:
                header = self.read_header(h)

            if header is not None:
                if header["powdata"]["algo"] == algo:
                    return {
                        "height": h,
                        "timestamp": header["timestamp"],
                        "bits": header["powdata"]["bits"],
                    }
                h -= 1
                continue

            # If the header is beyond the last checkpoint, it should
            # be there.
            if h > constants.net.max_checkpoint():
                raise MissingHeader(h)

            cp_data = self.checkpoints[h // 2016]
            algo_headers = cp_data["algo_headers"][f"{algo}"]

            # Check through the headers by decreasing height.  The first we
            # find that is <=h is ok.
            for hdr in algo_headers[::-1]:
                if hdr["height"] <= h:
                    return hdr

            raise MissingHeader (h)

    @classmethod
    def bits_to_target(cls, bits: int) -> int:
        bitsN = (bits >> 24) & 0xff
        # Mainnet has bits only up to 0x1e, but the regtest difficulty
        # starts with 0x20.  We want to support that as well, e.g. for
        # tests/test_blockchain.py.
        if not (0x03 <= bitsN <= 0x20):
            raise Exception("First part of bits should be in [0x03, 0x20], is: %x" % bits)
        bitsBase = bits & 0xffffff
        if not (0x8000 <= bitsBase <= 0x7fffff):
            raise Exception("Second part of bits should be in [0x8000, 0x7fffff]")
        return bitsBase << (8 * (bitsN-3))

    @classmethod
    def target_to_bits(cls, target: int) -> int:
        c = ("%064x" % target)[2:]
        while c[:2] == '00' and len(c) > 6:
            c = c[2:]
        bitsN, bitsBase = len(c) // 2, int.from_bytes(bfh(c[:6]), byteorder='big')
        if bitsBase >= 0x800000:
            bitsN += 1
            bitsBase >>= 8
        return bitsN << 24 | bitsBase

    def chainwork_of_header(self, header: dict) -> int:
        """work done by single header"""

        target = self.bits_to_target(header["powdata"]["bits"])

        work = ((2 ** 256 - target - 1) // (target + 1)) + 1
        work <<= difficulty.algo_log2_weight(header["powdata"]["algo"])

        return work

    @with_lock
    def get_chainwork(self, height=None) -> int:
        if height is None:
            height = max(0, self.height())

        if height == -1:
            return 0

        header = self.read_header(height)
        if header is not None:
            return header["chainwork"]

        if height <= constants.net.max_checkpoint():
            index = height // 2016
            if height == (index + 1) * 2016 - 1:
                return self.checkpoints[index]["chainwork"]

        raise MissingHeader(height)

    def can_connect(self, header: dict, check_height: bool=True, skip_auxpow: bool=False) -> bool:
        if header is None:
            return False
        height = header['block_height']
        if check_height and self.height() != height - 1:
            return False
        if height == 0:
            return hash_header(header) == constants.net.GENESIS
        try:
            prev_hash = self.get_hash(height - 1)
        except:
            return False
        if prev_hash != header.get('prev_block_hash'):
            return False
        try:
            target = self.get_expected_target(header)
        except MissingHeader:
            return False
        try:
            self.verify_header(header, prev_hash, target, skip_auxpow=skip_auxpow)
        except BaseException as e:
            return False
        return True

    def connect_chunk(self, idx: int, hexdata: str) -> bool:
        assert idx >= 0, idx
        try:
            data = bfh(hexdata)
            # verify_chunk also strips the AuxPoW headers
            data = self.verify_chunk(idx, data)
            self.save_chunk(idx, data)
            return True
        except BaseException as e:
            self.logger.info(f'verify_chunk idx {idx} failed: {repr(e)}')
            return False

    def get_checkpoints(self):
        # Due to continuous difficulty retargeting in Xaya, we need more
        # information than upstream with each checkpoint so that we can then
        # use it as basis for difficulty computations.  In particular, we
        # store the block hash, chainwork as well as the difficulty data
        # (bits, height and timestamp) of the last 24 blocks of each algorithm.
        cp = []

        n = self.height() // 2016

        for index in range(n):
            height = (index + 1) * 2016 - 1
            header = self.read_header(height)
            if header is None:
                raise MissingHeader(height)

            algo_headers = {}
            for algo in [powdata.ALGO_SHA256D, powdata.ALGO_NEOSCRYPT]:
                hdrs = []
                h = height
                while len(hdrs) < difficulty.NUM_BLOCKS:
                    next_hdr = self.difficulty_data_for_block(algo, h)
                    assert next_hdr is not None, (algo, h)
                    hdrs.append(next_hdr)
                    h = next_hdr["height"] - 1
                algo_headers[f"{algo}"] = hdrs[::-1]

            data = {
              "hash": hash_header(header),
              "chainwork": header["chainwork"],
              "algo_headers": algo_headers,
            }
            cp.append(data)
        return cp


def check_header(header: dict) -> Optional[Blockchain]:
    """Returns any Blockchain that contains header, or None."""
    if type(header) is not dict:
        return None
    with blockchains_lock: chains = list(blockchains.values())
    for b in chains:
        if b.check_header(header):
            return b
    return None


def can_connect(header: dict) -> Optional[Blockchain]:
    """Returns the Blockchain that has a tip that directly links up
    with header, or None.
    """
    with blockchains_lock: chains = list(blockchains.values())
    for b in chains:
        if b.can_connect(header):
            return b
    return None


def get_chains_that_contain_header(height: int, header_hash: str) -> Sequence[Blockchain]:
    """Returns a list of Blockchains that contain header, best chain first."""
    with blockchains_lock: chains = list(blockchains.values())
    chains = [chain for chain in chains
              if chain.check_hash(height=height, header_hash=header_hash)]
    chains = sorted(chains, key=lambda x: x.get_chainwork(), reverse=True)
    return chains
