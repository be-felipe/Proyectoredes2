import json
import os

tiposquerys = {
    b"\x00\x01": "a"
}
ZONES = {}


def cargarmaster():
    global ZONES
    arrreglozon = {}
    extencion = "Zones"
    files = []
    #abrimos los archivos con extencion Zones
    try:
        files = os.listdir(extencion)
    except FileNotFoundError:
        extencion = "..\Zones"
        files = os.listdir(extencion)
    for n in os.listdir(extencion):
        with open(os.path.join(extencion, n), "r") as t:
            datos = json.load(t)
            nombredelazona = datos["$origin"]
            arrreglozon[nombredelazona] = datos
    return arrreglozon
Zonas = cargarmaster()


def obtenerzone(domain):
        global Zonas
        nombrezona = ".".join(domain)
        arreglozona = {}
        try:
            arreglozona = Zonas[nombrezona]
        except KeyError:
            return None
        return arreglozona


class DNSGen(object):
     #atributos definidos rfc1035
    def __init__(self, datosudp):
        self.data = datosudp
        self.QR = "1"
        self.AA = "1"
        self.TC = "0"
        self.RD = "0"
        self.RA = "0"
        self.Z = "000"
        self.RCODE = "0000"
        self.QDCOUNT = b"\x00\01"
        self.NSCOUNT = b"\x00\x00"
        self.ARCOUNT = b"\x00\x00"
        self.error = 0
        self.domain = ""

    def obteneriddelatransaccion(self):
        # transaccion es d dos bits
        return self.data[0:2]

    def obteneropcode(self):
        byte1 = self.data[2:3]
        OPCODE  = ""
        for notd in range(1, 5):
            OPCODE  += str(ord(byte1) & (1 << notd))
        return OPCODE

    def banderas(self):
        bandera1 = int(self.QR + self.obteneropcode() + self.AA + self.TC + self.RD, 2).to_bytes(1, byteorder="big")
        bandera2 = int(self.RA + self.Z + self.RCODE).to_bytes(1, byteorder="big")
        return bandera1 + bandera2

    def obtenerpreguntacli(self, data):
        self.error = 0
        estado = 0
        tamano = 0
        dominios = ""
        listadominios = []
        tipoquery = None
        x = 0
        contadorbytes = 0
        try:
            for byte in data:
                if estado == 1:
                    if byte != 0:
                        #casteo a char
                        dominios += chr(byte)
                    x += 1
                    if x == tamano:
                        listadominios.append(dominios)
                        dominios = ""
                        estado = 0
                    if byte == 0:
                        listadominios.append(dominios)
                        break
                else:
                    estado = 1
                    tamano = byte
                contadorbytes += 1
            tipoquery = data[contadorbytes:contadorbytes+2]
            self.domain = ".".join(listadominios)
        except IndexError:
            self.error = 1
        finally:
            return listadominios, tipoquery

    def obtenerlosregistros(self, datos):
        dominio, tipoconsulta = self.obtenerpreguntacli(datos)
        if tipoconsulta is None and len(dominio) == 0:
            return {}, "", ""
        tiporegistro = ""
        try:
            tiporegistro = tiposquerys[tipoconsulta]
        except KeyError:
            tiporegistro = "a"
        zone = obtenerzone(dominio)
        if zone is None:
            return [], tiporegistro, dominio
        return zone[tiporegistro], tiporegistro, dominio

    @staticmethod
    def registroabytes(nombredominio, tiporegistro, ttl, valor):
        aux = b"\xc0\x0c"
        if tiporegistro == "a":
            aux += b"\x00\x01"
        aux += b"\x00\x01"
        aux += int(ttl).to_bytes(4, byteorder="big")
        if tiporegistro == "a":
            aux += b"\x00\x04"
            for xd in valor.split("."):
                aux += bytes([int(xd)])
        return aux

    def crearheader(self, tamano):
        idheader = self.obteneriddelatransaccion()
        ANCOUNT = tamano.to_bytes(2, byteorder="big")
        if self.error == 1:
            self.RCODE = "0001"
        elif ANCOUNT == b"\x00\x00":
            self.RCODE = "0003"
        banderas = self.banderas()
        return idheader + banderas + self.QDCOUNT + ANCOUNT + self.NSCOUNT + self.ARCOUNT

    def Realizarquery(self, tamano, tiporegistro, dominion):
        dest = b""
        if self.error == 1:
            return dest
        for noti in dominion:

            length = len(noti)

            dest += bytes([length])

            for char in noti:
                dest += ord(char).to_bytes(1, byteorder="big")
        dest += b"\x00"
        if tiporegistro == "a":

            dest += (1).to_bytes(2, byteorder="big")

        dest += (1).to_bytes(2, byteorder="big")
        return dest

    def Respuesta(self, registros, tipo, nombredominio):
        resp = b""
        if len(registros) == 0 or self.error == 1:
            return resp
        for notis in registros:
            resp += self.registroabytes(nombredominio, tipo, notis["ttl"], notis["value"])
        return resp

    def enviarrepuesta(self):
        registro, tipo, nombredominio = self.obtenerlosregistros(self.data[12:])
        return self.crearheader(len(registro)) + self.Realizarquery(len(registro), tipo, nombredominio) +\
               self.Respuesta(registro, tipo, nombredominio)


if __name__ == "__main__":
    pass
