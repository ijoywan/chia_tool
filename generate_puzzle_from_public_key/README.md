## generate puzzle from puzzle 

```py
from blspy import G1Element, PrivateKey
import hashlib
import io
from chia.bech32m import decode_puzzle_hash, encode_puzzle_hash
from chia.program import Program, SerializedProgram
from clvm_tools.binutils import assemble
from clvm.more_ops import op_sha256, op_pubkey_for_exp, op_point_add
from clvm.SExp import SExp, to_sexp_type
from stages.stage_0 import run_program as run_program_assemble

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
    ak = sha256([bytes(pk), DEFAULT_HIDDEN_PUZZLE_HASH])
    bk = pubkey_for_exp(to_sexp_type(ak))
    ck = point_add([pk, bk])
    return MOD.curry(bytes(ck))


pk = bytes.fromhex("88bc9360319e7c54ab42e19e974288a2d7a817976f7633f4b43f36ce72074e59c4ab8ddac362202f3e366f0aebbb6280")

## xch1zj28av8xnm50eqnery8u95uvkjamvxaz3udzwr8avsaqart4j4mqzlmzl5
puzzle = puzzle_for_pk(pk).get_tree_hash()
address = encode_puzzle_hash(puzzle, 'xch')
print(address)
```