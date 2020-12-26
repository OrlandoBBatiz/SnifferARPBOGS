#include <stdio.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <string.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <unistd.h>
#include <stdlib.h>
#include <net/if_arp.h>
#include <pthread.h>
#include <arpa/inet.h>

#define BUFFER 42
#define TAMANIO_MAC 6
#define TAMANIO_PROTOCOLO 4

typedef struct paq_ARP {
    unsigned char destinoEthernet[6];       
    unsigned char origenEthernet[6];        
    unsigned short tipoEthernet;            
    unsigned short tipoHardware;            
    unsigned short tipoProtocolo;          
    unsigned char longitudHardware;         
    unsigned char longitudProtocolo;        
    unsigned short tipoMensaje;             
    unsigned char origenMAC[TAMANIO_MAC];             
    unsigned char origenIP[TAMANIO_PROTOCOLO];              
    unsigned char destinoMAC[TAMANIO_MAC];            
    unsigned char destinoIP[TAMANIO_PROTOCOLO];             
}paq_ARP;

typedef struct datosUser{
	int	num_paquetes;
	char nom_de_adaptador[10];
}datosUser;

typedef struct userARP{
    int ID;
    char direccionIPDest[16];
    struct userARP *apSig;
    struct userARP *apAnt;
}userARP;

//Variables Globales
datosUser datosP;
pthread_mutex_t cerrojo = PTHREAD_MUTEX_INITIALIZER;

userARP * insertarNodo(int id,const char *ip,userARP *Inicio);
userARP * crearNodo(int id, const char *direccionIPDestino);
void imprimirListauserARP(userARP *Inicio);
void imprimirRespARP(paq_ARP *Inicio);

//Función Proceso del Hilo
void *protocoloARP(void *Inicio);

int main(){

    char cierre[50]="/sbin/ifconfig ";
    int i=0;
    int salida;


    printf("Ingrese el nombre de sus adaptador de red: ");
	fgets(datosP.nom_de_adaptador,10,stdin);
	strtok(datosP.nom_de_adaptador, "\n");

    printf("Ingrese el No. de Direcciones IP's a Resolver: ");
	scanf("%d",&datosP.num_paquetes);
    while (getchar() != '\n');
    

    printf("\n------------REPORTE------------\n\nNo. IP's: %d\nNombre de Adaptador: %s\n\n",datosP.num_paquetes,datosP.nom_de_adaptador);

    //Se crean variables de los hilos para el envio y recibo de paquetes ARP
    pthread_t hilosARP[datosP.num_paquetes];
    int hilosIDARP[datosP.num_paquetes];
    char ip[datosP.num_paquetes][16];
    userARP *filaARP = NULL;
    userARP *apRecorre = NULL;
    
    for (i=0; i < datosP.num_paquetes; i++){
        //while (getchar() != '\n');
        printf("Direcion IP %d: ",i+1);
        fgets(ip[i],sizeof(ip[i]),stdin);
        filaARP = insertarNodo(i,ip[i],filaARP);
    }
    
    //Creacion de hilos
    apRecorre = filaARP;
    for(i = 0; i<datosP.num_paquetes;i++){
        hilosIDARP[i] = pthread_create(&hilosARP[i],NULL,protocoloARP,apRecorre);
        if (hilosIDARP[i] == -1){
            printf("Error el crear el hilo\n\n");
        }
        apRecorre = apRecorre->apSig;
    }
    
    for (i=0; i<datosP.num_paquetes; i++){
        hilosIDARP[i] = pthread_join(hilosARP[i],(void **)&salida);
        
    }

    strcat(cierre,datosP.nom_de_adaptador);
	strcat(cierre," -promisc");
	system(cierre);

    return 0;
}

userARP * insertarNodo(int id,const char *ip,userARP *Inicio){
    
    userARP * nuevoNodo = crearNodo(id,ip);
    userARP * apRecorre = NULL;
    
    if(Inicio == NULL){
        //Primero de la lista
        Inicio = nuevoNodo;
        return Inicio;
    }
    else{
        apRecorre = Inicio;
        while(apRecorre->apSig != NULL){
            apRecorre = apRecorre->apSig;
        }
        apRecorre->apSig = nuevoNodo;

        return Inicio;
    }
}

userARP * crearNodo(int id, const char *direccionIPDestino){

    userARP *NuevoNodo;

    NuevoNodo = (userARP*)malloc(sizeof(userARP));
    if(NuevoNodo == NULL){
        printf("No se creo nodo userARP\n\n");
    }
    else{
        NuevoNodo->ID = id;
        strcpy(NuevoNodo->direccionIPDest,direccionIPDestino);
        NuevoNodo->apSig = NULL;
    }

    return NuevoNodo;

}

void imprimirListauserARP(userARP *Inicio){

    userARP *apRecorre = Inicio;
    while (apRecorre != NULL)
    {
        printf("ID: %d, IP: %s\n",apRecorre->ID,apRecorre->direccionIPDest);
        apRecorre = apRecorre->apSig;
    }
    
}

void *protocoloARP(void *Inicio){
    userARP * nuevoNodo = (userARP *)Inicio;
    int idARP = nuevoNodo->ID;
    unsigned char ip[16];
    strcpy(ip,(const char*)nuevoNodo->direccionIPDest);

    struct ifreq ethreq;
    int optval;
    char nombre_de_Adaptador[10];

    paq_ARP bufferARP;
    char buffer[BUFFER];
    int idSocket; // Sockets
    //Direcciones Origen ARP
    unsigned char direccionorigenMAC[TAMANIO_MAC];
    unsigned char direccionorigenIP[TAMANIO_PROTOCOLO];
    //DIrecciones Destino ARP
    unsigned char direcciondestinoIP[TAMANIO_PROTOCOLO];
    unsigned char auxsrcIP[TAMANIO_PROTOCOLO];
    int m=0;
    int j=0;
    char aux[4];

    int i=0;

    strcpy(nombre_de_Adaptador,datosP.nom_de_adaptador);

    //printf("Me encuentro en el hilo %d\n\n",idARP);
    //Pasar la Direccion IP destino de strin a un arreglo de 4 enteros
    j=0;
    while(i != sizeof(ip) && j<=3){
        aux[m]=ip[i];
        if(ip[i]=='.' || ip[i] == '\0'){
            aux[3]='\0';
            direcciondestinoIP[j] = (unsigned char)atoi(aux);
            m=0;
            j++;
        }
        else{
            m++;
        }
        
        i++;
    }

    for(i=0; i < TAMANIO_PROTOCOLO; i++) {
        auxsrcIP[i]=direcciondestinoIP[i];
        printf("%d.",direcciondestinoIP[i]);
    }
    printf("\n\n");

    
    //Creacion de socket
    memset(&ethreq,0,sizeof(struct ifreq));
    idSocket = socket(PF_PACKET,SOCK_PACKET,htons(ETH_P_ARP));
    if(idSocket <0){
        printf("Error al generar el socket %d\n\n",idARP);
        exit(1);
    }

    //Configurar el socket a modo difusión
    setsockopt(idSocket,SOL_SOCKET,SO_BROADCAST,&optval,sizeof(optval));
    strncpy(ethreq.ifr_name,datosP.nom_de_adaptador,IFNAMSIZ);
    ioctl (idSocket,SIOCGIFFLAGS, &ethreq);
	ethreq.ifr_flags |= IFF_PROMISC;
    ioctl(idSocket, SIOCSIFFLAGS, &ethreq);
	ioctl (idSocket, SIOCGIFADDR, &ethreq);

    //Obtenemos las direcciones que tenemos en nuestra Computadora

    memcpy(direccionorigenIP,ethreq.ifr_addr.sa_data,TAMANIO_MAC);
    ioctl(idSocket, SIOCGIFHWADDR, &ethreq);
    memcpy(direccionorigenMAC, ethreq.ifr_hwaddr.sa_data, TAMANIO_MAC);

    
    paq_ARP mensajeARP;
    

    //Lenamos de datos nuestros mensaje ARP a Enviar
    for (i = 0; i < TAMANIO_MAC; i++) {
        //Direccion Broadcast En la TRAMA ETHERNET
        mensajeARP.destinoEthernet[i] = 0xFF; 
    }
    for (i = 0; i < TAMANIO_MAC; i++) {
        //Dirección MAC Origen EN LA TRAMA ETHERNET
        mensajeARP.origenEthernet[i] =direccionorigenMAC[i]; 
    }
    //Inicia Paquete ARP
    mensajeARP.tipoEthernet = htons(ETH_P_ARP);
    mensajeARP.tipoHardware = htons(ARPHRD_ETHER);
    mensajeARP.tipoProtocolo = htons(ETH_P_IP);
    mensajeARP.longitudHardware = TAMANIO_MAC;
    mensajeARP.longitudProtocolo = TAMANIO_PROTOCOLO;
    mensajeARP.tipoMensaje = htons(ARPOP_REQUEST);

    for (i = 0; i < TAMANIO_MAC; i++) {
        //Direccion MAC Origen en ARP
        mensajeARP.origenMAC[i] = direccionorigenMAC[i];
    }
    for (i = 0; i < TAMANIO_PROTOCOLO; i++) {
        //Dirección IP Origen en ARP
        mensajeARP.origenIP[i] = direccionorigenIP[i+2];
        
    }
    for (i = 0; i < TAMANIO_MAC; i++) {
        //Dirección MAC Destino llena de 00 porque no hay ninguna aun
        mensajeARP.destinoMAC[i] = 0x00;
    }
    for (i = 0; i < TAMANIO_PROTOCOLO; i++) {
        //Dirección IP Destino
        mensajeARP.destinoIP[i] = auxsrcIP[i];
    }
    /*
    printf("---------IMPRESION DE MENSAJE ARP A ENVIAR---------\n\n");
    printf("Dirección destino Ethernet:\t");
    for(int i=0;i<4;i++){
        printf("%02x:",mensajeARP.destinoEthernet[i]);
    }
    printf("\nDirección origen Ethernet:\t");
    for(int i=0;i<4;i++){
        printf("%02x:",mensajeARP.origenEthernet[i]);
    }
    printf("Tipo Ethernet: %d\n",mensajeARP.tipoEthernet);
    printf("Tipo Hardware: %d\n",mensajeARP.tipoHardware);
    printf("Tipo Protocolo: %d\n",mensajeARP.tipoProtocolo);
    printf("Longitud Hardware: %d\n",mensajeARP.longitudHardware);
    printf("Longitud Protocolo: %d\n",mensajeARP.longitudProtocolo);
    printf("Tipo Mensake %d\n",mensajeARP.tipoMensaje);

    printf("\nDirección origen MAC:\t");
    for(int i=0;i<6;i++){
        printf("%02x:",mensajeARP.origenMAC[i]);
    }
    printf("\nDirección origen IP:\t");
    for(int i=0;i<4;i++){
        printf("%d.",mensajeARP.origenIP[i]);
    }
    printf("\nDirección destino MAC:\t");
    for(int i=0;i<6;i++){
        printf("%02x:",mensajeARP.destinoMAC[i]);
    }
    printf("\nDirección destino IP:\t");
    for(i=0; i < TAMANIO_PROTOCOLO; i++) {
        printf("%d.",mensajeARP.destinoIP[i]);
    }
    printf("\n\n");

    */
    struct sockaddr addr;
    strncpy(addr.sa_data, nombre_de_Adaptador, sizeof(addr.sa_data));
    ssize_t bytesSent;

    paq_ARP respARP;
    ssize_t bytesReceived = 0;
    int correct; 
    int rec=0;
    do {

        rec++;
        bytesSent = sendto(idSocket, &mensajeARP, BUFFER, 0, &addr, sizeof(addr));

        if (bytesSent <= 0) {
            perror("error bye");
            exit(EXIT_FAILURE);
        }

        pthread_mutex_lock(&cerrojo);
        if (rec>2) {
          printf("\n\nSe agoto el tiempo para: ");
          for (int i = 0; i < TAMANIO_PROTOCOLO; i++) printf("%d ", auxsrcIP[i]);
          pthread_mutex_unlock(&cerrojo);
          close(idSocket);
          pthread_exit(&idARP);
        } else {
          //printf("\n\tRequest enviada\n");
        }
        pthread_mutex_unlock(&cerrojo);

        do {
            bytesReceived = recvfrom(idSocket, &bufferARP, BUFFER, 0, NULL, NULL);
            respARP = bufferARP;
        } while (htons(respARP.tipoMensaje) == 1);

        correct = 1;
        for (int j = 0; j < TAMANIO_PROTOCOLO; ++j) {
            if (respARP.origenIP[j] != auxsrcIP[j]){
                correct = 0;
                break;
            }
        }

    } while (!correct);

    pthread_mutex_lock(&cerrojo);
    imprimirRespARP(&respARP);
    pthread_mutex_unlock(&cerrojo);

    close(idSocket);

    pthread_exit(&idARP);

}

void imprimirRespARP(paq_ARP *Inicio){
    int i =0;
    printf("-----------Respuesta ARP-----------\n\n");
    printf("\nDirección MAC origen:\t");
    for(i=0; i < TAMANIO_MAC; i++) {
        printf("%02x:",Inicio->origenMAC[i]);
    }
    printf("\nDirecciónIP origen:\t");
    for(i=0; i < TAMANIO_PROTOCOLO; i++) {
        printf("%d.",Inicio->origenIP[i]);
    }
    printf("\n\nMAC destino:\t");
    for(i=0; i < TAMANIO_MAC; i++) {
        printf("%02x:",Inicio->destinoMAC[i]);
    }
    printf("\nIP destino:\t");
    for(i=0; i < TAMANIO_PROTOCOLO; i++) {
        printf("%d.",Inicio->destinoIP[i]);
    }
    printf("\n");
}