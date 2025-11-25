import asyncio
import random
import time
from tcputils import *

class Servidor:
    def __init__(self, rede, porta):
        self.rede = rede
        self.porta = porta
        self.conexoes = {}
        self.callback = None
        self.rede.registrar_recebedor(self._rdt_rcv)

    def registrar_monitor_de_conexoes_aceitas(self, callback):
        self.callback = callback

    def _rdt_rcv(self, src_addr, dst_addr, segment):
        src_port, dst_port, seq_no, ack_no, \
            flags, window_size, checksum, urg_ptr = read_header(segment)

        if dst_port != self.porta:
            return
        if not self.rede.ignore_checksum and calc_checksum(segment, src_addr, dst_addr) != 0:
            print('descartando segmento com checksum incorreto')
            return

        payload = segment[4*(flags>>12):]
        id_conexao = (src_addr, src_port, dst_addr, dst_port)

        if (flags & FLAGS_SYN) == FLAGS_SYN:
            conexao = Conexao(self, id_conexao, seq_no)
            self.conexoes[id_conexao] = conexao
            if self.callback:
                self.callback(conexao)
        elif id_conexao in self.conexoes:
            self.conexoes[id_conexao]._rdt_rcv(seq_no, ack_no, flags, payload)
        else:
            print('%s:%d -> %s:%d (pacote associado a conexão desconhecida)' %
                  (src_addr, src_port, dst_addr, dst_port))

class Conexao:
    def __init__(self, servidor, id_conexao, seq_no_cliente):
        self.servidor = servidor
        self.id_conexao = id_conexao
        self.callback = None

        # Gera número de sequência inicial aleatório para o servidor
        self.seq_no = random.randint(0, 0xffffffff)
        # Define o próximo número de sequência esperado do cliente
        self.ack_no = seq_no_cliente + 1

        # Estado da conexão
        self.estado = "SYN_RCVD"

        # Guarda o número de sequência inicial do cliente
        self.seq_no_cliente_inicial = seq_no_cliente

        # Controle de envio: fila de segmentos a enviar e flag de segmento pendente
        self._fila_envio = []  # lista de bytes (payloads)
        self._enviando = False # True se há segmento aguardando ACK
        self._ultimo_segmento_enviado = None # (payload, tamanho, segmento_completo)

        # Para cálculo do RTT adaptativo
        self._estimated_rtt = None
        self._dev_rtt = None
        self._alpha = 0.125  # Fator para EstimatedRTT
        self._beta = 0.25    # Fator para DevRTT
        self._timeout_interval = 1.0  # Valor inicial conservador
        self._tempo_envio = None      # Momento do último envio (para cálculo do SampleRTT)
        self._segmento_pendente_medicao = False  # Se o segmento pendente é elegível para medição

        # Envia SYN+ACK para completar o handshake
        self._enviar(FLAGS_SYN | FLAGS_ACK)

    def _start_timeout(self):
        if hasattr(self, '_timeout_handle') and self._timeout_handle:
            self._timeout_handle.cancel()
        loop = asyncio.get_event_loop()
        self._timeout_handle = loop.call_later(self._timeout_interval, self._retransmitir)

    def _cancel_timeout(self):
        if hasattr(self, '_timeout_handle') and self._timeout_handle:
            try:
                self._timeout_handle.cancel()
            except Exception:
                pass
            self._timeout_handle = None

    def _retransmitir(self):
        # Retransmite o último segmento enviado
        if self._enviando and self._ultimo_segmento_enviado:
            src_addr, src_port, dst_addr, dst_port = self.id_conexao
            segmento = self._ultimo_segmento_enviado[2]
            self.servidor.rede.enviar(segmento, src_addr)
            # Marca que não devemos medir RTT para retransmissões
            self._segmento_pendente_medicao = False
            # Reagenda o timeout
            self._start_timeout()

    def _atualizar_rtt(self, sample_rtt):
        """Atualiza EstimatedRTT e DevRTT conforme RFC 2988"""
        if self._estimated_rtt is None:
            # Primeira medição - inicializa conforme RFC 2988
            self._estimated_rtt = sample_rtt
            self._dev_rtt = sample_rtt / 2
        else:
            # Atualiza EstimatedRTT: EWMA
            self._estimated_rtt = (1 - self._alpha) * self._estimated_rtt + self._alpha * sample_rtt
            # Atualiza DevRTT: EWMA do desvio absoluto
            deviation = abs(sample_rtt - self._estimated_rtt)
            self._dev_rtt = (1 - self._beta) * self._dev_rtt + self._beta * deviation
        
        # Calcula novo timeout interval
        self._timeout_interval = self._estimated_rtt + 4 * max(self._dev_rtt, 0.01)
        
        # Limites mínimos e máximos razoáveis para evitar timeout muito pequeno ou muito grande
        self._timeout_interval = max(0.1, min(self._timeout_interval, 10.0))

    def _enviar(self, flags, payload=b''):
        src_addr, src_port, dst_addr, dst_port = self.id_conexao
        segmento = make_header(dst_port, src_port, self.seq_no, self.ack_no, flags)
        segmento += payload
        segmento = fix_checksum(segmento, src_addr, dst_addr)
        self.servidor.rede.enviar(segmento, src_addr)

    def _rdt_rcv(self, seq_no, ack_no, flags, payload):
        # Se recebeu FIN, notifica aplicação e ajusta estado
        if (flags & FLAGS_FIN) == FLAGS_FIN:
            if self.callback:
                self.callback(self, b"")
            self.estado = "FECHADA"
            # Envia ACK de fechamento
            self.ack_no += 1
            self._enviar(FLAGS_ACK)
            return

        # Tratamento do handshake - ACK do SYN+ACK
        if self.estado == "SYN_RCVD":
            if (flags & FLAGS_ACK) == FLAGS_ACK and ack_no == self.seq_no + 1:
                self.estado = "ESTABLISHED"
                # O número de sequência do servidor deve ser incrementado após o SYN
                self.seq_no += 1
            return

        # Em estado estabelecido, processa dados
        if self.estado == "ESTABLISHED":
            # Se recebeu FIN, notifica aplicação e ajusta estado
            if (flags & FLAGS_FIN) == FLAGS_FIN:
                if self.callback:
                    self.callback(self, b"")
                self.estado = "FECHADA"
                # Envia ACK de fechamento
                self._enviar(FLAGS_ACK)
                return

            # Verifica se é um ACK válido (com dados ou apenas confirmação)
            if (flags & FLAGS_ACK) == FLAGS_ACK:
                # Se tem payload, processa os dados
                if len(payload) > 0:
                    # Verifica se o segmento está em ordem
                    if seq_no == self.ack_no:
                        # Entrega os dados para a camada de aplicação
                        if self.callback:
                            self.callback(self, payload)
                        # Atualiza o próximo número de sequência esperado
                        self.ack_no += len(payload)
                    # Sempre envia ACK em resposta
                    self._enviar(FLAGS_ACK)

                # Controle de envio: libera próximo segmento se ACK confirma o último enviado
                if self._enviando and ack_no > self.seq_no:
                    # Calcula SampleRTT apenas para transmissões originais (não retransmissões)
                    if self._segmento_pendente_medicao and self._tempo_envio is not None:
                        sample_rtt = time.time() - self._tempo_envio
                        self._atualizar_rtt(sample_rtt)
                    
                    # Atualiza seq_no com base no ack_no recebido
                    bytes_confirmados = ack_no - self.seq_no
                    self.seq_no = ack_no
                    
                    self._enviando = False
                    self._ultimo_segmento_enviado = None
                    self._tempo_envio = None
                    self._segmento_pendente_medicao = False
                    self._cancel_timeout()
                    # Tenta enviar próximo segmento, se houver
                    self._tentar_enviar_proximo()

    def registrar_recebedor(self, callback):
        self.callback = callback

    def enviar(self, dados):
        # Não envia nada se não houver dados
        if len(dados) == 0:
            return

        # Fragmenta e adiciona à fila de envio
        for i in range(0, len(dados), MSS):
            segmento_dados = dados[i:i+MSS]
            self._fila_envio.append(segmento_dados)

        # Se não há segmento pendente, envia o próximo
        self._tentar_enviar_proximo()

    def _tentar_enviar_proximo(self):
        if not self._enviando and self._fila_envio:
            segmento_dados = self._fila_envio.pop(0)
            src_addr, src_port, dst_addr, dst_port = self.id_conexao
            segmento = make_header(dst_port, src_port, self.seq_no, self.ack_no, FLAGS_ACK)
            segmento += segmento_dados
            segmento = fix_checksum(segmento, src_addr, dst_addr)
            self.servidor.rede.enviar(segmento, src_addr)
            
            self._enviando = True
            self._ultimo_segmento_enviado = (segmento_dados, len(segmento_dados), segmento)
            self._tempo_envio = time.time()  # Registra momento do envio para cálculo do RTT
            self._segmento_pendente_medicao = True  # Este segmento é elegível para medição de RTT
            
            self._start_timeout()

    def fechar(self):
        src_addr, src_port, dst_addr, dst_port = self.id_conexao
        self.seq_no += 1
        segmento = make_header(dst_port, src_port, self.seq_no, self.ack_no, FLAGS_FIN | FLAGS_ACK)
        segmento = fix_checksum(segmento, src_addr, dst_addr)
        self.servidor.rede.enviar(segmento, src_addr)

#teste  teste teste
