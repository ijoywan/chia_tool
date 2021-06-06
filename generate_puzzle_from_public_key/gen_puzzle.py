from blspy import G1Element, PrivateKey
import hashlib
import io
from chia.ints import uint32
from chia.bech32m import decode_puzzle_hash, encode_puzzle_hash
from chia.program import Program, SerializedProgram
from clvm_tools.binutils import assemble
from clvm.more_ops import op_sha256, op_pubkey_for_exp, op_point_add
from clvm.SExp import SExp, to_sexp_type
from stages.stage_0 import run_program as run_program_assemble
from chia.derive_keys import master_sk_to_wallet_sk

private_key = bytes.fromhex("xxxxxx")

DEFAULT_HIDDEN_PUZZLE_HASH = bytes.fromhex('711d6c4e32c92e53179b199484cf8c897542bc57f2b22582799f9d657eec4699')


clvm_blob = bytes.fromhex('ff02ffff01ff02ffff03ff0bffff01ff02ffff03ffff09ff05ffff1dff0bffff1effff0bff0bffff02ff06ffff04ff02ffff04ff17ff8080808080808080ffff01ff02ff17ff2f80ffff01ff088080ff0180ffff01ff04ffff04ff04ffff04ff05ffff04ffff02ff06ffff04ff02ffff04ff17ff80808080ff80808080ffff02ff17ff2f808080ff0180ffff04ffff01ff32ff02ffff03ffff07ff0580ffff01ff0bffff0102ffff02ff06ffff04ff02ffff04ff09ff80808080ffff02ff06ffff04ff02ffff04ff0dff8080808080ffff01ff0bffff0101ff058080ff0180ff018080')
MOD = Program.from_bytes(bytes(SerializedProgram.from_bytes(clvm_blob)))

def point_add(items):
    '''
    '''
    p = G1Element()
    for kk in items:
        try:
            p += G1Element.from_bytes(kk)
        except Exception as ex:
            raise ValueError("point_add expects blob, got")
    return p

def sha256(args):
    h = hashlib.sha256()
    for k in args:
        h.update(k)
    return h.digest()

def int_from_bytes(blob):
    return int.from_bytes(blob, "big", signed=True)


def args_as_ints(args):
    for arg in args:
        yield int_from_bytes(arg)

def pubkey_for_exp(args):
    ((i0),) = args_as_ints([args])
    i0 %= 0x73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFF00000001
    exponent = PrivateKey.from_bytes(i0.to_bytes(32, "big"))
    return bytes(exponent.get_g1())

def puzzle_for_pk(public_key: G1Element) -> Program:
    ak = sha256([bytes(public_key), DEFAULT_HIDDEN_PUZZLE_HASH])
    bk = pubkey_for_exp(to_sexp_type(ak))
    ck = point_add([public_key, bk])
    return MOD.curry(bytes(ck))


def create_more_puzzle_hashes(private_key, start_index=0):
    to_generate = 100

    derivation_paths = []

    for index in range(start_index, to_generate):

        pubkey = master_sk_to_wallet_sk(private_key, uint32(index)).get_g1()
        puzzle = puzzle_for_pk(bytes(pubkey))
        if puzzle is None:
            print(f"Unable to create puzzles with wallet")
            break
        puzzlehash = puzzle.get_tree_hash()
        print(f"Puzzle at index {index} wallet puzzle hash {puzzlehash.hex()}")
        derivation_paths.append(
            {
                "index": uint32(index),
                "puzzle": puzzlehash,
                "pubkey": pubkey
            }
        )
    return derivation_paths



if __name__ == '__main__':

    pk = PrivateKey.from_bytes(private_key)
    print(create_more_puzzle_hashes(pk, 0))