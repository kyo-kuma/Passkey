from dnslib import DNSRecord, QTYPE, RR, A
from dnslib.server import DNSServer, BaseResolver, DNSLogger
import sys
import logging

class CustomResolver(BaseResolver):
    def __init__(self, address, ttl=60):
        self.address = address
        self.ttl = ttl

    def resolve(self, request, handler):
        reply = request.reply()
        qname = request.q.qname
        if request.q.qtype == 1:
            qtype = 'A'
        elif request.q.qtype == 28:
            qtype = 'AAAA'
        else:
            qtype = ''

        # 特定のドメイン名に対する処理
        if qname.matchGlob('apbil1236762.ap.brothergroup.net.'):
            reply.add_answer(RR(qname, QTYPE.A, rdata=A(self.address), ttl=self.ttl))
        else:
            # その他の要求は外部DNSに転送
            try:
                if handler.protocol == 'udp':
                    proxy_r = DNSRecord.parse(DNSRecord.question(qname, qtype).send('192.168.128.1', 53))
                else:
                    proxy_r = DNSRecord.parse(DNSRecord.question(qname, qtype).send('192.168.128.1', 53, tcp=True))
                for rr in proxy_r.rr:
                    reply.add_answer(rr)
            except Exception as e:
                print("Failed to forward request: %s" % e, file=sys.stderr)
        return reply

def start():
    logging.basicConfig(level=logging.ERROR)
    print("dns server start")
    resolver = CustomResolver('192.168.128.108')
    server = DNSServer(resolver, port=53, address='0.0.0.0', logger=DNSLogger(prefix=False))
    server.start()

def main():
    start()

if __name__ == '__main__':
    main()
