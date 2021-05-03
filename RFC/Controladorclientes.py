import threading
from RFC import DNSGen


class Controladorclientes(threading.Thread):


    def __init__(self, direcciondp, datosudp, sock):
        threading.Thread.__init__(self)
        self.direcciondp = direcciondp
        self.generador = DNSGen(datosudp)
        self.sock = sock

    def iniciar(self):
        resp = self.generador.enviarrepuesta()
        self.sock.sendto(self.generador.enviarrepuesta(), self.direcciondp)
        print("peticion del cliente desde direccion {0} y nombrehost {1}".format(self.direcciondp, self.generador.domain))
