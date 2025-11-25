from iputils import *
import struct

class IP:
    def __init__(self, enlace):
        """
        Inicia a camada de rede. Recebe como argumento uma implementação
        de camada de enlace capaz de localizar os next_hop (por exemplo,
        Ethernet com ARP).
        """
        self.callback = None
        self.enlace = enlace
        self.enlace.registrar_recebedor(self.__raw_recv)
        self.ignore_checksum = self.enlace.ignore_checksum
        self.meu_endereco = None
        self._tabela = []

    def __raw_recv(self, datagrama):
        dscp, ecn, identification, flags, frag_offset, ttl, proto, \
           src_addr, dst_addr, payload = read_ipv4_header(datagrama, verify_checksum=not self.ignore_checksum)
        if dst_addr == self.meu_endereco:
            # atua como host
            if proto == IPPROTO_TCP and self.callback:
                self.callback(src_addr, dst_addr, payload)
        else:
            # atua como roteador
            next_hop = self._next_hop(dst_addr)
            # Trata corretamente o campo TTL do datagrama
            if ttl <= 1:
                # TTL expirou: envie ICMP Time Exceeded para o remetente (src_addr)
                # Construir mensagem ICMP: tipo 11, código 0, 4 bytes zero, seguido dos primeiros 28 bytes do datagrama original
                icmp_hdr = struct.pack('!BBH4s', 11, 0, 0, b'\x00\x00\x00\x00')
                icmp_payload = icmp_hdr + datagrama[:28]
                # calcule checksum do ICMP (colocando-o nos bytes 2:4)
                icmp_msg = bytearray(icmp_payload)
                ck = calc_checksum(bytes(icmp_msg))
                icmp_msg[2:4] = struct.pack('!H', ck)
                icmp_msg = bytes(icmp_msg)

                # Montar cabeçalho IP para o pacote ICMP
                src = self.meu_endereco if self.meu_endereco is not None else '0.0.0.0'
                version_ihl = (4 << 4) | 5
                dscpecn = 0
                total_len = 20 + len(icmp_msg)
                identification = 0
                flagsfrag = 0
                ttl_new = 64
                proto_icmp = IPPROTO_ICMP
                checksum = 0
                src_b = str2addr(src)
                dst_b = str2addr(src_addr)  # destino do ICMP é o remetente original
                ip_hdr = struct.pack('!BBHHHBBH4s4s', version_ihl, dscpecn, total_len,
                                     identification, flagsfrag, ttl_new, proto_icmp,
                                     checksum, src_b, dst_b)
                ch = calc_checksum(ip_hdr)
                ip_hdr = struct.pack('!BBHHHBBH4s4s', version_ihl, dscpecn, total_len,
                                     identification, flagsfrag, ttl_new, proto_icmp,
                                     ch, src_b, dst_b)
                icmp_datagram = ip_hdr + icmp_msg
                self.enlace.enviar(icmp_datagram, next_hop)
            else:
                # decrementa TTL, atualiza checksum do cabeçalho e encaminha
                new_dat = bytearray(datagrama)
                new_dat[8] = ttl - 1  # byte do TTL
                # zera checksum e recalcula
                new_dat[10:12] = b'\x00\x00'
                hdr = bytes(new_dat[:20])
                chk = calc_checksum(hdr)
                new_dat[10:12] = struct.pack('!H', chk)
                self.enlace.enviar(bytes(new_dat), next_hop)

    def _next_hop(self, dest_addr):
        # Converte IP para inteiro
        def ip2int(a):
            p = [int(x) for x in a.split('.')]
            return (p[0]<<24) | (p[1]<<16) | (p[2]<<8) | p[3]

        dest_int = ip2int(dest_addr)
        best = None
        best_prefix = -1
        for net_int, mask_int, prefixlen, next_hop in self._tabela:
            if (dest_int & mask_int) == net_int:
                if prefixlen > best_prefix:
                    best_prefix = prefixlen
                    best = next_hop
        return best

    def definir_endereco_host(self, meu_endereco):
        """
        Define qual o endereço IPv4 (string no formato x.y.z.w) deste host.
        Se recebermos datagramas destinados a outros endereços em vez desse,
        atuaremos como roteador em vez de atuar como host.
        """
        self.meu_endereco = meu_endereco

    def definir_tabela_encaminhamento(self, tabela):
        """
        Define a tabela de encaminhamento no formato
        [(cidr0, next_hop0), (cidr1, next_hop1), ...]

        Onde os CIDR são fornecidos no formato 'x.y.z.w/n', e os
        next_hop são fornecidos no formato 'x.y.z.w'.
        """
        def ip2int(a):
            p = [int(x) for x in a.split('.')]
            return (p[0]<<24) | (p[1]<<16) | (p[2]<<8) | p[3]
        def mask_from_prefix(n):
            if n == 0:
                return 0
            return (0xffffffff << (32 - n)) & 0xffffffff

        nova = []
        for cidr, next_hop in tabela:
            ip_part, prefix = cidr.split('/')
            prefix = int(prefix)
            mask = mask_from_prefix(prefix)
            net_int = ip2int(ip_part) & mask
            nova.append((net_int, mask, prefix, next_hop))
        # ordena por prefixo decrescente para facilitar lookup por maior prefixo
        nova.sort(key=lambda x: -x[2])
        self._tabela = nova

    def registrar_recebedor(self, callback):
        """
        Registra uma função para ser chamada quando dados vierem da camada de rede
        """
        self.callback = callback

    def enviar(self, segmento, dest_addr):
        """
        Envia segmento para dest_addr, onde dest_addr é um endereço IPv4
        (string no formato x.y.z.w).
        """
        next_hop = self._next_hop(dest_addr)
        src = self.meu_endereco if self.meu_endereco is not None else '0.0.0.0'
        version_ihl = (4 << 4) | 5
        dscpecn = 0
        total_len = 20 + len(segmento)
        identification = 0
        flagsfrag = 0
        ttl = 64
        proto = IPPROTO_TCP
        checksum = 0
        src_b = str2addr(src)
        dst_b = str2addr(dest_addr)
        ip_hdr = struct.pack('!BBHHHBBH4s4s', version_ihl, dscpecn, total_len,
                             identification, flagsfrag, ttl, proto,
                             checksum, src_b, dst_b)
        ch = calc_checksum(ip_hdr)
        ip_hdr = struct.pack('!BBHHHBBH4s4s', version_ihl, dscpecn, total_len,
                             identification, flagsfrag, ttl, proto,
                             ch, src_b, dst_b)
        datagrama = ip_hdr + segmento
        self.enlace.enviar(datagrama, next_hop)

# Implementa a camada de rede IPv4, capaz de agir como Host ou Roteador. 
# Como Host, ele recebe pacotes destinados a si mesmo e os entrega à camada superior.
#  Como Roteador, ele encaminha pacotes para outros destinos: consulta sua tabela de roteamento (usando Longest Prefix Match), 
#  decrementa o TTL (Time-To-Live) e recalcula o checksum antes de enviar. 
# Se o TTL expirar, ele descarta o pacote e envia um ICMP "Time Exceeded" de volta à origem.