# cifrador_pbm.py
import os
import random

# --- Módulo de cifragem/decifragem conforme CA-1.0 de Gutowitz ---

def carregarImagemBinaria(path):
    """Carrega PBM/binário P4 com header e retorna dados brutos"""
    with open(path, 'rb') as f:
        magic = f.readline().strip()
        if magic != b'P4':
            raise ValueError(f"Formato suportado apenas P4 (PBM binário), recebeu: {magic}")
        # header: dimensões apenas
        while True:
            line = f.readline()
            if not line.startswith(b'#'):
                dims = line.strip().split()
                break
        width, height = map(int, dims)
        data = f.read()
    return magic, width, height, data


def bytesParaBits(data):
    bits = []
    for b in data:
        for i in range(8)[::-1]:
            bits.append((b >> i) & 1)
    return bits


def bitsParaBytes(bits):
    b = bytearray()
    for i in range(0, len(bits), 8):
        byte = 0
        for bit in bits[i:i+8]:
            byte = (byte << 1) | bit
        b.append(byte)
    return bytes(b)


def dividirEmBlocos(bits, block_size=384):
    pad = (-len(bits)) % block_size
    if pad:
        bits.extend([0]*pad)
    n = len(bits) // block_size
    blocks = [bits[i*block_size:(i+1)*block_size] for i in range(n)]
    return blocks, pad


def gerarLinkAleatorio(bits_len=320):
    return os.urandom(bits_len//8)


def gerarKeystream(link):
    # inicialmente 64 bits do link
    state = [(link[i] >> (7-(j))) & 1 for i in range(len(link)) for j in range(8)]
    state = state[:64]
    ks = []
    for _ in range(6):
        ks.extend(state)
        nxt = []
        for i in range(64):
            left = state[i-1] if i>0 else 0
            center = state[i]
            right = state[i+1] if i<63 else 0
            nxt.append(left ^ (center | right))
        state = nxt
    return ks


def faseDifusao(bits_blk, link, key_bits):
    ks = gerarKeystream(link)
    # extende chave para 384 bits
    ext = key_bits * ((384//len(key_bits))+1)
    ext = ext[:384]
    return [b ^ k ^ c for b,k,c in zip(bits_blk, ks, ext)]


def faseDifusaoInversa(bits_blk, link, key_bits):
    return faseDifusao(bits_blk, link, key_bits)


def faseSubstituicao(bits_blk, link):
    # permutação determinística via shuffle seed=hash(link)
    seed = int.from_bytes(link, 'big')
    rnd = random.Random(seed)
    perm = list(range(len(bits_blk)))
    rnd.shuffle(perm)
    return [bits_blk[i] for i in perm]


def faseSubstituicaoInversa(bits_blk, link):
    seed = int.from_bytes(link, 'big')
    rnd = random.Random(seed)
    perm = list(range(len(bits_blk)))
    rnd.shuffle(perm)
    inv = [0]*len(bits_blk)
    for i,p in enumerate(perm): inv[p] = bits_blk[i]
    return inv


def cifragem(input_path, output_path, key_path):
    magic, w, h, data = carregarImagemBinaria(input_path)
    with open(key_path, 'rb') as f:
        key_bits = bytesParaBits(f.read())

    bits = bytesParaBits(data)
    blocks, pad = dividirEmBlocos(bits)

    with open(output_path, 'wb') as f:
        # header
        f.write(b'P4\n')
        f.write(f"{w} {h}\n".encode())
        # pad byte
        f.write(bytes([pad]))
        # cada bloco: link + dados
        for blk in blocks:
            link = gerarLinkAleatorio()
            diff = faseDifusao(blk, link, key_bits)
            sub = faseSubstituicao(diff, link)
            f.write(link)
            f.write(bitsParaBytes(sub))


def decifragem(input_path, output_path, key_path):
    magic, w, h, data = carregarImagemBinaria(input_path)
    with open(key_path, 'rb') as f:
        key_bits = bytesParaBits(f.read())

    pad = data[0]
    stream = data[1:]
    link_len = 40
    chunk = link_len + 48
    n = len(stream) // chunk

    bits = []
    for i in range(n):
        base = i*chunk
        link = stream[base:base+link_len]
        cipher = stream[base+link_len:base+chunk]
        sub = bytesParaBits(cipher)
        inv_sub = faseSubstituicaoInversa(sub, link)
        inv_diff = faseDifusaoInversa(inv_sub, link, key_bits)
        bits.extend(inv_diff)

    if pad: bits = bits[:-pad]
    data_out = bitsParaBytes(bits)

    with open(output_path, 'wb') as f:
        f.write(b'P4\n')
        f.write(f"{w} {h}\n".encode())
        f.write(data_out)
