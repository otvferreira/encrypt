import os
import math

# --- Constante ---
BLOCK_BITS = 384  # tamanho fixo do bloco em bits

# --- Funções de leitura e escrita NetPBM ---
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

def _escreverCabecalho(f, magic, w, h, maxval):
    f.write(magic + b"\n")
    f.write(f"{w} {h}\n".encode())
    if maxval is not None:
        f.write(f"{maxval}\n".encode())

# --- Conversão bytes <-> bits ---
def bytesParaBits(data):
    bits = []
    for byte in data:
        for i in range(8)[::-1]:
            bits.append((byte >> i) & 1)
    return bits

def bitsParaBytes(bits):
    ba = bytearray()
    for i in range(0, len(bits), 8):
        v = 0
        for bit in bits[i:i+8]:
            v = (v << 1) | bit
        ba.append(v)
    return bytes(ba)

# --- Divisão em blocos + padding ---
def dividirEmBlocos(bits, block_size=BLOCK_BITS):
    pad = (-len(bits)) % block_size
    if pad:
        bits.extend([0] * pad)
    n = len(bits) // block_size
    blocks = [bits[i*block_size:(i+1)*block_size] for i in range(n)]
    return blocks, pad

# --- Geração de keystream (Regra 30) ---
def gerarKeystream(seed_bytes):
    state = [(seed_bytes[i] >> (7-j)) & 1
             for i in range(len(seed_bytes)) for j in range(8)]
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

# --- Geração de link interno pela CA (Regra 30 sobre a chave) ---
def gerarLinkInterno(key_bytes, link_bits_len=320):
    # Converte a chave em keystream de 384 bits
    ks = gerarKeystream(key_bytes)
    bits = ks[:link_bits_len]
    return bitsParaBytes(bits)

# --- Fase de Difusão ---
def faseDifusao(bits_blk, link, key_bits):
    ks = gerarKeystream(link)
    ext = key_bits * ((BLOCK_BITS // len(key_bits)) + 1)
    ext = ext[:BLOCK_BITS]
    return [b ^ k ^ c for b,k,c in zip(bits_blk, ks, ext)]

def faseDifusaoInversa(bits_blk, link, key_bits):
    return faseDifusao(bits_blk, link, key_bits)

# --- Substituição via Árvore Binária ---
def _gerar_permutacao_arvore(bits_len, link_bits):
    m = 1 << math.ceil(math.log2(bits_len))
    idxs = list(range(bits_len)) + [None] * (m - bits_len)
    perm = []
    it = iter(link_bits)
    def recurse(lst):
        if len(lst) == 1:
            perm.append(lst[0])
            return
        mid = len(lst) // 2
        L, R = lst[:mid], lst[mid:]
        if next(it, 0) == 0:
            recurse(L)
            recurse(R)
        else:
            recurse(R)
            recurse(L)
    recurse(idxs)
    return [i for i in perm if i is not None]

def faseSubstituicao(bits_blk, link):
    link_bits = bytesParaBits(link)
    perm = _gerar_permutacao_arvore(BLOCK_BITS, link_bits)[:len(bits_blk)]
    return [bits_blk[i] for i in perm]

def faseSubstituicaoInversa(sub_bits, link):
    link_bits = bytesParaBits(link)
    perm = _gerar_permutacao_arvore(BLOCK_BITS, link_bits)[:len(sub_bits)]
    inv = [0] * len(sub_bits)
    for i, dst in enumerate(perm):
        inv[dst] = sub_bits[i]
    return inv

# --- Operações principais ---
def cifragem(input_path, output_path, key_path):
    magic, w, h, maxval, data = carregarImagemBinaria(input_path)
    key_bytes = open(key_path, 'rb').read()
    key_bits = bytesParaBits(key_bytes)
    bits = bytesParaBits(data)
    blocks, pad = dividirEmBlocos(bits)
    with open(output_path, 'wb') as f:
        _escreverCabecalho(f, magic, w, h, maxval)
        f.write(bytes([pad]))
        for blk in blocks:
            link = gerarLinkInterno(key_bytes)
            diff = faseDifusao(blk, link, key_bits)
            sub  = faseSubstituicao(diff, link)
            f.write(link)
            f.write(bitsParaBytes(sub))

def decifragem(input_path, output_path, key_path):
    magic, w, h, maxval, raw = carregarImagemBinaria(input_path)
    key_bytes = open(key_path, 'rb').read()
    key_bits = bytesParaBits(key_bytes)
    pad = raw[0]
    stream = raw[1:]
    link_len = len(gerarLinkInterno(key_bytes))
    chunk = link_len + (BLOCK_BITS // 8)
    n = len(stream) // chunk
    bits = []
    for i in range(n):
        base = i * chunk
        vetor_cifrado = stream[base:base+link_len]
        bloco_cifrado = stream[base+link_len:base+chunk]
        sb = bytesParaBits(bloco_cifrado)
        inv_sub  = faseSubstituicaoInversa(sb, vetor_cifrado)
        inv_diff = faseDifusaoInversa(inv_sub, vetor_cifrado, key_bits)
        bits.extend(inv_diff)
    if pad:
        bits = bits[:-pad]
    data_out = bitsParaBytes(bits)
    with open(output_path, 'wb') as f:
        _escreverCabecalho(f, magic, w, h, maxval)
        f.write(data_out)
