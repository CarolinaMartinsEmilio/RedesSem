class CamadaEnlace:
    ignore_checksum = False

    def __init__(self, linhas_seriais):
        """
        Inicia uma camada de enlace com um ou mais enlaces, cada um conectado
        a uma linha serial distinta. O argumento linhas_seriais é um dicionário
        no formato {ip_outra_ponta: linha_serial}. O ip_outra_ponta é o IP do
        host ou roteador que se encontra na outra ponta do enlace, escrito como
        uma string no formato 'x.y.z.w'. A linha_serial é um objeto da classe
        PTY (vide camadafisica.py) ou de outra classe que implemente os métodos
        registrar_recebedor e enviar.
        """
        self.enlaces = {}
        self.callback = None
        # Constrói um Enlace para cada linha serial
        for ip_outra_ponta, linha_serial in linhas_seriais.items():
            enlace = Enlace(linha_serial)
            self.enlaces[ip_outra_ponta] = enlace
            enlace.registrar_recebedor(self._callback)

    def registrar_recebedor(self, callback):
        """
        Registra uma função para ser chamada quando dados vierem da camada de enlace
        """
        self.callback = callback

    def enviar(self, datagrama, next_hop):
        """
        Envia datagrama para next_hop, onde next_hop é um endereço IPv4
        fornecido como string (no formato x.y.z.w). A camada de enlace se
        responsabilizará por encontrar em qual enlace se encontra o next_hop.
        """
        # Encontra o Enlace capaz de alcançar next_hop e envia por ele
        self.enlaces[next_hop].enviar(datagrama)

    def _callback(self, datagrama):
        if self.callback:
            self.callback(datagrama)


class Enlace:
    def __init__(self, linha_serial):
        self.linha_serial = linha_serial
        self._recv_buffer = bytearray()  
        self._escape = False              
        self._bad = False                
        self.linha_serial.registrar_recebedor(self.__raw_recv)

    def registrar_recebedor(self, callback):
        self.callback = callback

    def enviar(self, datagrama):
        meio = bytearray()
        for b in datagrama:
            if b == 0xC0:
                meio.extend(b'\xDB\xDC')
            elif b == 0xDB:
                meio.extend(b'\xDB\xDD')
            else:
                meio.append(b)
        quadro = b'\xC0' + bytes(meio) + b'\xC0'
        self.linha_serial.enviar(quadro)

    def __raw_recv(self, dados):
        import traceback

        for byte in dados:
            if byte == 0xC0:
                # fim de quadro (ou possível início de quadro vazio)
                if not self._bad and len(self._recv_buffer) > 0:
                    datagrama = bytes(self._recv_buffer)
                    try:
                        if self.callback:
                            self.callback(datagrama)
                    except Exception:
                        # mostra exceção, mas garante limpeza do buffer para não
                        # reapresentar restos do datagrama
                        traceback.print_exc()
                    finally:
                        # sempre limpar estado do quadro atual
                        self._recv_buffer = bytearray()
                        self._escape = False
                        self._bad = False
                else:
                    # se quadro vazio ou mal formado: apenas resetamos o estado
                    self._recv_buffer = bytearray()
                    self._escape = False
                    self._bad = False
                # continue para próxima iteração (0xC0 não faz parte do datagrama)
                continue

            # se chegamos aqui, não é delimitador
            if self._bad:
                # já marcado como mal formado: ignorar bytes até próximo 0xC0
                continue

            if self._escape:
                # estamos esperando o byte de escape
                if byte == 0xDC:
                    self._recv_buffer.append(0xC0)
                elif byte == 0xDD:
                    self._recv_buffer.append(0xDB)
                else:
                    # sequência inválida: marca quadro como mal formado
                    self._bad = True
                self._escape = False
            else:
                if byte == 0xDB:
                    # marca que estamos em modo escape; pode ficar pendente entre chunks
                    self._escape = True
                else:
                    # byte normal: anexa
                    self._recv_buffer.append(byte)
