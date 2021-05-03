import socket

from RFC import Controladorclientes

# Global variables
Localhost = "127.0.0.1"
Puerto = 53


def main():
    #ipv4
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    #configura ip y puerto
    sock.bind((Localhost, Puerto))
    print("Servidor  en ip-puerto {0}:{1} ...".format(Localhost, Puerto))
    while True:
        print('Bienvenido al servidor DNS ')
        datosudp, direcciondp = sock.recvfrom(512)
        manejadorcliente = Controladorclientes(direcciondp, datosudp, sock)
        manejadorcliente.iniciar()


if __name__ == "__main__":
    main()
