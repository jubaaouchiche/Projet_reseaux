

### Projet : analyseur de protocoles

L’objectif de ce projet est de programmer un analyseur de protocoles réseau
‘oﬄine’. Il prend en entrée un fichier trace contenant les octets capturés
préalablement sur un réseau Ethernet. Ce programme a été codé en python(3).

### Archive



- Le fichier contenant le code source du projet qui est "analyser.py".
- Le fichier howto qui explique comment lancer le programme. 
- Quelques fichiers (.txt) contenant les trames à analyser et  la sortie de la fonction(resultatanalyser).

### Lacement du programme

1-Tout d'abord il faut installer python3.

2-Pour lancer le programme, il faut:
	-Ouvrir un termimal puis accèder au répertoire du dossier compressé ensuite  lancer la commande "make".

3-Une fois l'execution faite le programme affiche "Veuillez selectionner un fichier " dans ce cas alors vous devez taper le nom d'un fichier existant dans le meme repertoire.

## Résultat

Le programme va analyser la(les) trame(s) du fichier passé en parametre et renvoie un autre fichier qui contient le résultat de l'analyse :
- Les lignes supprimées
- Le nombre de trames erronées.
- Le nombre de trames correctes.
- le resultat de l'analyse de toutes les trames.

## Les Protocoles + options supportées 

#1-Couche 02 : Ethernet

- Adresse MAC Destination qui est sous format aa:bb:cc:dd:ee:ff
- Adresse MAC Source qui est sous format aa:bb:cc:dd:ee:ff
- Affiche le type du protocol :  qui sont ARP(0806) et IPV4 (0800).

#2-Couche 03 :IP 

#Protocole :IPV4

Le programme traite que l'IPv4 il affiche ses champs :

- Version(4).
- Header Length : qui est la longueur de l'entete au max 60Bytes.
- Les drapeaux :reserved bit, don't fragment, more fragments..
- Total length : qui est la longueur totale du datagramme IP
- Time to Live
- Protocol: UDP encapsulé dans le datagramme
- Header Checksum 
- Source IP address 
- Destination address 
!! Dans ce programme on affiche pas le champs data/payload.



#Options IPV4

L'entete du datagramme IP contient des options ssi sa longueur est superieure à 20 octets en decimal, les options traitées :

- End of Options List
- Router Alert
- Strict Source Route
- No Operation 
- Record Route
- Loose Source Route


#Protocol : ARP
- Harware type, exemple Ethernet (1)
- Protocol type, exemple IPv4 (0x8000)
- Hardware size, pour ethernet : 6
- Protocol size, pour IPv4 : 4
- Opcode 
- Sender Harware address
- Sender Protocol address
- Receiver Harware address
- Receiver Protocol address





#3-Couche 04 :UDP

Si le numéro du protocol encapsulé dans le datagramme IP est égal à 17 en decimal, alors c'est UDP

- Port source
- Port destination
- Longueur du packet
- La valeur du checksum (unverified)



#4-Couche Application :DNS ET DHCP


