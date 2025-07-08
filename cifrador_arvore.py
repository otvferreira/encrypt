import os
import random
import math

BLOCK_BITS = 384  # tamanho fixo para permutação em árvore

def carregarImagemBinaria(path):
    with open(path, 'rb') as f:
        magic = f.readline().strip()
        if magic not in (b'P4', b'P5', b'P6'):
            raise ValueError(f"Formato não suportado: {magic.decode()}")
        tokens = []
        needed = 2 if magic == b'P4' else 3
        while len(tokens) < needed:
            line = f.readline()
            if not line.startswith(b'#'):
                tokens.extend(line.split())
        w, h = map(int, tokens[:2])
        maxval = int(tokens[2]) if magic in (b'P5', b'P6') else None
        data = f.read()
    return magic, w, h, maxval, data


def bytesParaBits(data):
    bits = []
    for byte in data:
        for i in range(8)[::-1]:
            bits.append((byte >> i) & 1)
    return bits


def bitsParaBytes(bits):
    ba = bytearray()
    for i in range(0, len(bits), 8):
        b = 0
        for bit in bits[i:i+8]:
            b = (b << 1) | bit
        ba.append(b)
    return bytes(ba)


def dividirEmBlocos(bits, block_size=BLOCK_BITS):
    pad = (-len(bits)) % block_size
    if pad:
        bits.extend([0]*pad)
    n = len(bits)//block_size
    blocks = [bits[i*block_size:(i+1)*block_size] for i in range(n)]
    return blocks, pad


def gerarLinkAleatorio(bits_len=320):
    return os.urandom(bits_len//8)


def gerarKeystream(link):
    state = [(link[i] >> (7-j)) & 1 for i in range(len(link)) for j in range(8)]
    state = state[:64]
    ks = []
    for _ in range(6):
        ks.extend(state)
        nxt = []
        for i in range(64):
            l = state[i-1] if i>0 else 0
            c = state[i]
            r = state[i+1] if i<63 else 0
            nxt.append(l ^ (c | r))
        state = nxt
    return ks


def _escreverCabecalho(f, magic, w, h, maxval):
    f.write(magic + b"\n")
    f.write(f"{w} {h}\n".encode())
    if maxval is not None:
        f.write(f"{maxval}\n".encode())

# --- Difusão CA-1.0 ---
def faseDifusao(bits_blk, link, key_bits):
    ks = gerarKeystream(link)
    ext = key_bits * ((BLOCK_BITS//len(key_bits))+1)
    ext = ext[:BLOCK_BITS]
    return [b ^ k ^ c for b,k,c in zip(bits_blk, ks, ext)]

def faseDifusaoInversa(bits_blk, link, key_bits):
    return faseDifusao(bits_blk, link, key_bits)

def _gerar_permutacao_arvore(bits_len, link_bits):
    """
    Gera permutação de 0..bits_len-1 usando árvore binária completa.
    """
    # Número de folhas = próximo 2^k >= bits_len
    m = 1 << math.ceil(math.log2(bits_len))
    # Lista de índices com padding None
    idxs = list(range(bits_len)) + [None] * (m - bits_len)
    perm = []
    it = iter(link_bits)

    def recurse(node_list):
        if len(node_list) == 1:
            perm.append(node_list[0])
            return
        mid = len(node_list) // 2
        left = node_list[:mid]
        right = node_list[mid:]
        bit = next(it, 0)
        if bit == 0:
            recurse(left)
            recurse(right)
        else:
            recurse(right)
            recurse(left)

    recurse(idxs)
    # Filtrar valores None e retornar apenas permutação válida
    return [i for i in perm if i is not None]


def faseSubstituicao(bits_blk, link):
    link_bits = bytesParaBits(link)
    # Gera permutação para todo o bloco
    perm_full = _gerar_permutacao_arvore(BLOCK_BITS, link_bits)
    # Aplica apenas aos bits presentes
    perm = perm_full[:len(bits_blk)]
    return [bits_blk[i] for i in perm]


def faseSubstituicaoInversa(sub_bits, link):
    link_bits = bytesParaBits(link)
    perm_full = _gerar_permutacao_arvore(BLOCK_BITS, link_bits)
    perm = perm_full[:len(sub_bits)]
    inv = [0] * len(sub_bits)
    for i, dst in enumerate(perm):
        inv[dst] = sub_bits[i]
    return inv

# --- Operações principais ---
def cifragem(input_path, output_path, key_path):
    magic, w, h, maxval, data = carregarImagemBinaria(input_path)
    key_bits = bytesParaBits(open(key_path,'rb').read())
    bits = bytesParaBits(data)
    blocks, pad = dividirEmBlocos(bits)
    with open(output_path,'wb') as f:
        _escreverCabecalho(f, magic, w, h, maxval)
        f.write(bytes([pad]))
        for blk in blocks:
            link = gerarLinkAleatorio()
            diff = faseDifusao(blk, link, key_bits)
            sub = faseSubstituicao(diff, link)
            f.write(link)
            f.write(bitsParaBytes(sub))


def decifragem(input_path, output_path, key_path):
    magic, w, h, maxval, raw = carregarImagemBinaria(input_path)
    key_bits = bytesParaBits(open(key_path,'rb').read())
    pad = raw[0]
    stream = raw[1:]
    link_len = 40
    chunk = link_len + (BLOCK_BITS//8)
    n = len(stream)//chunk
    bits = []
    for i in range(n):
        base = i*chunk
        link = stream[base:base+link_len]
        cipher = stream[base+link_len:base+chunk]
        subb = bytesParaBits(cipher)
        inv_sub = faseSubstituicaoInversa(subb, link)
        inv_diff = faseDifusaoInversa(inv_sub, link, key_bits)
        bits.extend(inv_diff)
    if pad:
        bits = bits[:-pad]
    data_out = bitsParaBytes(bits)
    with open(output_path,'wb') as f:
        _escreverCabecalho(f, magic, w, h, maxval)
        f.write(data_out)
