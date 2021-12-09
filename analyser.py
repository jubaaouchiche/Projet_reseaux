# Projet_reseaux:


#--------------------------------------------------------------------------------------------------------Fichier Parse------------------------------------------------------------------------------------------------

def FichierParse (file):
    """Cette fonction lit le fichier qui contenant les trames à analyser.
    Argument :  un fichier dans le meme repertoire.
    Retourne  un dictionnaire des trames correctes et de trames erronees et les lignes qui sont fausses dans les trames erronees .
    
    """
    OffsetCourant = 0

    Lignes = file.readlines()

    LignesValides, PositionLignes = [], {}
    

    for ind in range(len(Lignes)):

        Ligne = Lignes[ind].strip().lower()
        #On enleve les espaces à gauche et à droite puis mettre les caracteres en minuscule

        if Ligne :
            Offset = Ligne.split(maxsplit=1)[0] 																						#Lecture  de l'offset du debut de ligne
        else:
            Offset = ""

        if OffsetValide(Offset, OffsetCourant):
            OffsetCourant = int(Offset, 16)
            PositionLignes[Ligne] = ind
            LignesValides.append(Ligne) 																								#On ajoute l'offset dans le tableau ssi il est valide
        else:
            print("Ligne supprimee  :  ", Lignes[ind])

    TramesCorrectes = []
    TramesErronees = []
    ListeDesLignesErronees = []

    for ind in range(len(LignesValides)):

        OffsetCourant = int(LignesValides[ind].split(maxsplit=1)[0], 16)
        if ind+1 == len(LignesValides) : 
            OffsetSuivant = 0
        else:
            OffsetSuivant = int(LignesValides[ind+1].split(maxsplit=1)[0], 16)

        if OffsetCourant == 0:
            Trame = []
            TrameValidee = True
        
        splittedLine = LignesValides[ind].split()

        if OffsetSuivant != 0 :
            NmbrOctetsSurLaLigne = OffsetSuivant - OffsetCourant

            if SequenceOctetValide(splittedLine[1:], NmbrOctetsSurLaLigne) : 
                Trame.extend(splittedLine[1:NmbrOctetsSurLaLigne+1])
            else:
                ListeDesLignesErronees.append(PositionLignes[LignesValides[index]])
                TrameValidee = False
        else: 
            

            if Trame[12]+Trame[13] == "0806":   
                LongueurTrame = 60-14         
            else :
                if len(Trame) > 18:  
                    LongueurTrame = int(Trame[16]+Trame[17], 16)
                else:
                    LongueurTrame = -1
                    if len(splittedLine[1:]) > 18 - len(Trame) :  
                        try:
                            LongueurTrame = int(splittedLine[17-len(Trame)]+splittedLine[18-len(Trame)], 16)
                        except: 
                            TrameValidee = False
                            ListeDesLignesErronees.append(PositionLignes[LignesValides[ind]])
                            print("Champs longueur totale du datagramme IP érroné ligne erronée : numéro :", PositionLignes[LignesValides[ind]])
            NmbrOctetsSurLaLigne = LongueurTrame + 14 - len(Trame)     									#LongueurTrame représente la longueur totale de la Trame
                                                                    																			     
            if SequenceOctetValide(splittedLine[1:], NmbrOctetsSurLaLigne) :
                print(splittedLine[1:NmbrOctetsSurLaLigne+1])
                Trame.extend(splittedLine[1:NmbrOctetsSurLaLigne+1])
            else:
                TrameValidee = False
                ListeDesLignesErronees.append(PositionLignes[LignesValides[ind]])

            if TrameValidee :
                TramesCorrectes.append(Trame)
            else:
                TramesErronees.append(Trame)

    return {"trames correctes" : TramesCorrectes,
            "trames erronees" : TramesErronees,
            "lignes erronees" : ListeDesLignesErronees,
            }


#----------------------------------------------------------------------------------------------------Couche 02: Ethernet--------------------------------------------------------------------------------------------


def Ethernet (Trame) : 
    """Cette fonction analyse la Trame Ethernet  et affiche ses champs 
    Argument : Trame à analyser
    """
    TypeDeProtocol = {"0800": "IPVersion4", "080": "", "0806" : "ARP"}
    
    AdrDestination = Trame[0]+":"+Trame[1]+":"+Trame[2]+":"+Trame[3]+":"+Trame[4]+":"+Trame[5]
    AdrSource = Trame[6]+":"+Trame[7]+":"+Trame[8]+":"+Trame[9]+":"+Trame[10]+":"+Trame[11]
    
    typee = Trame[12]+Trame[13]
    
    print("   "+Colors.BOLD+Colors.UNDERLINE+"Protocol Ethernet:"+Colors.ENDC)
    print("\t\tDestination: {}".format(AdrDestination))
    print("\t\tSource: {}".format(AdrSource))

    if(typee in TypeDeProtocol.keys()):
    
        print("\t\tType:  {}  (0x{}) ".format(TypeDeProtocol[typee], typee))
        outputFile.write("\t\tType:  {}  (0x{}) \n".format(TypeDeProtocol[typee], typee))
    
    outputFile.write("   Protocol Ethernet:\n")
    outputFile.write("\t\tDestination: {}\n".format(AdrDestination))
    outputFile.write("\t\tSource: {}\n".format(AdrSource))
   
    if typee == "0800":
        IPVersion4(Trame)
    
    elif typee == "0806":
        ARP(Trame)
    
    else :
        print(Colors.WARNING+Colors.BOLD+"   Protocol numéro {} non supporté".format(typee)+Colors.ENDC)
        outputFile.write("   Protocol numéro {} non supporté\n".format(typee))

def Layers (Dico):
    
    Trames = Dico["trames correctes"]
    NmbrTrames = len(Trames)
    
    print(Colors.FAIL+Colors.BOLD+" Le nombre de trames erronees est : " + str(len(Dico["trames erronees"])) + Colors.ENDC)
    outputFile.write(" Le nombre de trames erronees est : " + str(len(Dico["trames erronees"]))+"\n")

    for ligne in Dico["lignes erronees"]:
        print("\t\tLigne numero {} erronnée ou imcomplète".format(ligne))
        outputFile.write("\t\tLigne numero {} erronnée ou imcomplète\n".format(ligne))

    print(Colors.OKGREEN+Colors.BOLD+" Le nombre de trames correctes est : "+ str(NmbrTrames)+ Colors.ENDC+"\n")
    outputFile.write(" Le nombre de trames correctes est : "+ str(NmbrTrames)+"\n"+"\n")

    for Trame, i  in zip(Trames, range(len(Trames))) :
        print(Colors.WARNING+" Trame numero {} : -- {} octets --".format(i, len(Trame))+Colors.ENDC)
        outputFile.write(" Trame {} : -- {} octets --\n".format(i, len(Trame)))
        try :
            Ethernet(Trame)
        except Exception as excep:
            if hasattr(excep, 'message'):
                print(excep.message)
            else:
                print(excep)
            
        print("\n")
        outputFile.write("\n")


    

def SequenceOctetValide(SequenceOctet, NmbrOctets): 
    """Cette fonction lit la sequences d'octets passée en arguments .
    Arguments : 1)-> Sequence d'octets,
    				   2)->  Nombre d'octets.
    Retourne : True si tous les nombres d'octets sont des caracteres hexadecimaux, False sinon
    """
    fin = False
    dd = 0
    
    while not fin :
        if NmbrOctets == 0 :
            return True
        try:
            int(SequenceOctet[dd], 16)                                                                                           
        except:
            return False

        dd+=1
        NmbrOctets-=1


def OffsetValide(OffsetCourant, OffsetPrecedant):
    """Cette fonction compare les deux arguments renvoie True si le premier est superieur au deuxieme Offset . 
    Arguments : 1)-> Offset courant,
                       2)-> Offset precedant.
    Retourne : True si l'Offset courant est valide c'est à dire si il est superieur à l'Offset  precedant)
    """
    try:
        Offs = int(OffsetCourant, 16) 																
    except:
        return False
    
    if Offs == 0 :
        return True
    
    return Offs >= OffsetPrecedant 







#------------------------------------------------------------------------------------------------------Couches 3: IP--------------------------------------------------------------------------------------------------

def IPVersion4(Trame):
    """Cette fonction analyse le datagramme IP version 4  affiche ses champs
    Argument : Trame à analyser
    """
    
    Offset = 14                                                                                #Début du datagramme IPVersion4 par rapport au début de la Trame
    Protocols= {1: "ICMP", 2 : "IGMP", 6 : "TCP", 17: "UDP", 36 : "XTP"}

    Version = Trame[Offset+0][0]

    HeaderLength32 = int(Trame[Offset+0][1], 16)  

    if HeaderLength32<5 :
        raise ValueError("	La Valeur minimum du header IP est 20 octets.")

    Tos =  Trame[Offset+1]

    TotalLength = Trame[Offset+2]+Trame[Offset+3]
    

    Id = Trame[Offset+4]+Trame[Offset+5]
    PremierByte = format(int(Trame[Offset+6], 16), '08b')
    DeuxiemeByte = format(int(Trame[Offset+7], 16), '08b')
    ReservedBit = PremierByte[0]
    DFragment = PremierByte[1]
    MFragment = PremierByte[2]
    FragOffset = PremierByte[3:]+DeuxiemeByte

    Ttl = Trame[Offset+8]
    Protocol = int(Trame[Offset+9], 16)
    
    HeaderChecksum =Trame[Offset+10]+Trame[Offset+11]
    
    Srce_addr= '.'.join([str(int(x,16)) for x in Trame[Offset+12:Offset+16]])
    Des_addr='.'.join([str(int(x,16)) for x in Trame[Offset+16:Offset+20]])
    
    OptionsTypes = 1

    print("   "+Colors.BOLD+Colors.UNDERLINE+"Internet Protocol Version 4:"+Colors.ENDC)
    print("\t\t{} .... = Version: 4 ".format(format(int(Version, 16), '04b')))
    print("\t\t.... {} = Header Length: {} bytes ({}) ".format(format(int(str(HeaderLength32), 16), '04b'),int(str(HeaderLength32),16)*4,HeaderLength32))
    print("\t\tIdentification: 0x{} ({})".format(Id,int(Id,16)))

    Dic_not_set={"0":"Not set","1":"Set"}

    print("\t\tFlags: 0x{} ".format(Trame[Offset+6]))
    print("\t\t\t{}... .... = Reserved bit: {} ".format(ReservedBit,Dic_not_set[ReservedBit]))
    print("\t\t\t.{}.. .... = Don't fragment: {} ".format(DFragment,Dic_not_set[DFragment]))
    print("\t\t\t..{}. .... = More fragments: {} ".format(MFragment,Dic_not_set[MFragment]))
    print("\t\tTotal Length: {}".format(int(TotalLength,16)))
    print("\t\tTime to Live: {}".format(int(Ttl,16)))

    if(Protocol in Protocols.keys()):
        print("\t\tProtocol: {} ({})".format(Protocols[Protocol],Protocol))
        outputFile.write("\t\tProtocol: {} ({})\n".format(Protocols[Protocol],Protocol))

    print("\t\tHeader Checksum: 0x{}".format(HeaderChecksum))
    print("\t\tSource Address: {}".format(Srce_addr))
    print("\t\tDestination Address: {}".format(Des_addr))


    outputFile.write("   Internet Protocol Version 4:\n")
    outputFile.write("\t\t{} .... = Version: 4 \n".format(format(int(Version, 16), '04b')))
    outputFile.write("\t\t.... {} = Header Length: {} bytes ({}) \n".format(format(int(str(HeaderLength32), 16), '04b'),int(str(HeaderLength32),16)*4,HeaderLength32))
    outputFile.write("\t\t\tIdentification: 0x{} ({})\n".format(Id,int(Id,16)))
    outputFile.write("\t\tFlags: 0x{} \n".format(Trame[Offset+6]))
    outputFile.write("\t\t\t{}... .... = Reserved bit: {} \n".format(ReservedBit,Dic_not_set[ReservedBit]))
    outputFile.write("\t\t\t.{}.. .... = Don't fragment: {} \n".format(DFragment,Dic_not_set[DFragment]))
    outputFile.write("\t\t\t..{}. .... = More fragments: {} \n".format(MFragment,Dic_not_set[MFragment]))
    outputFile.write("\t\tTotal Length: {}\n".format(int(TotalLength,16)))
    outputFile.write("\t\tTime to Live: {}\n".format(int(Ttl,16)))
    outputFile.write("\t\tHeader Checksum: 0x{}\n".format(HeaderChecksum))
    outputFile.write("\t\tSource Address: {}\n".format(Srce_addr))
    outputFile.write("\t\tDestination Address: {}\n".format(Des_addr))

#-----------------------------------------------------------------------------------------------------OPTIONS IP-----------------------------------------------------------------------------------------------------

    
    if (HeaderLength32 > 5):                             

        NmbrOctetsOptions = (HeaderLength32 - 5) * 4
        print("\t\tOptions: {} bytes".format(NmbrOctetsOptions))

        outputFile.write("\tOptions: {} bytes\n".format(NmbrOctetsOptions))

        off = Offset+20

        while True : 
            if NmbrOctetsOptions == 0 : 
                break
            PremierOctetOption = Trame[off]              
            if (int(PremierOctetOption, 16) == 0):
                print("\t\t  IP Option  -  End of Options List (EOL)")
                outputFile.write("\t\t  IP Option  -  End of Options List (EOL)\n")
                print("\t\t\tType: 0")
                outputFile.write("\t\t\tType: 0\n")
                off+=1
                NmbrOctetsOptions -=1
            elif (int(PremierOctetOption, 16) == 1):
                print("\t\t  IP Option  -  No Operation (NOP)")
                outputFile.write("\t\t  IP Option  -  No Operation (NOP)\n")
                print("\t\t\tType: 1")
                outputFile.write("\t\tType: 1\n")
                off+=1
                NmbrOctetsOptions -=1
            elif (int(PremierOctetOption, 16) == 7):
                print("\t\t  IP Option  -  Record Route (RR)")
                outputFile.write("\t\t  IP Option  -  Record Route (RR)\n")

                print("\t\t\tType: 7")
                outputFile.write("\t\t\tType: 7\n")

                Length = int(Trame[off+1], 16)
                print("\t\t\tLength: {}".format(Length))

                outputFile.write("\t\t\tLength: {}\n".format(Length))

                Pointer = int(Trame[off+2], 16)

                print("\t\t\tPointer: {}".format(Pointer))
                outputFile.write("\t\t\tPointer: {}\n".format(Pointer))

                for i in range((Length-3)//4):
                    RR= '.'.join([str(int(x,16)) for x in Trame[off+3+i*4:off+7+i*4]])
                    print("\t\t\tRecorded Route: {}".format(RR))
                    outputFile.write("\t\t\tRecorded Route: {}\n".format(RR))
                
                off+=Length
                NmbrOctetsOptions -= Length

            elif (int(PremierOctetOption, 16) == 131):
                print("\t\t  IP Option  -  Loose Source Route (LSR)")
                outputFile.write("\t\t  IP Option  -  Loose Source Route (LSR)\n")

                print("\t\t\tType: 131")
                outputFile.write("\t\t\tType: 131\n")

                Length = int(Trame[off+1], 16)
                print("\t\tLength: {}".format(Length))
                outputFile.write("\t\tLength: {}\n".format(Length))
                Pointer = int(Trame[off+2], 16)

                print("\t\t\tPointer: {}".format(Pointer))
                outputFile.write("\t\t\tPointer: {}\n".format(Pointer))

                for i in range((Length-3)//4):
                    Route= '.'.join([str(int(x,16)) for x in Trame[off+3+i*4:off+7+i*4]])
                    print("\t\t\tRoute: {}".format(Route)) 
                    outputFile.write("\t\t\tRoute: {}\n".format(Route))
                off+=Length
                NmbrOctetsOptions -= Length

            elif (int(PremierOctetOption, 16) == 137):
                print("\t\t  IP Option  -  Strict Source Route (SSR)")
                outputFile.write("\t\t  IP Option  -  Strict Source Route (SSR)\n")

                print("\t\tType: 137")
                outputFile.write("\t\tType: 137\n")
                Length = int(Trame[off+1], 16)

                print("\t\tLength: {}".format(Length))
                outputFile.write("\t\tLength: {}\n".format(Length))
                Pointer = int(Trame[off+2], 16)

                print("\t\t\tPointer: {}".format(Pointer))
                outputFile.write("\t\t\tPointer: {}\n".format(Pointer))

                for i in range((Length-3)//4):
                    Route= '.'.join([str(int(x,16)) for x in Trame[off+3+i*4:off+7+i*4]])
                    print("\t\t\tRoute: {}".format(Route)) 
                    outputFile.write("\t\t\tRoute: {}\n".format(Route)) 
                off+=Length
                NmbrOctetsOptions -= Length

            elif (int(PremierOctetOption, 16) == 148):
                print("\t\t\t   IP Option  -  Router Alert ")
                outputFile.write("\t\t\t  IP Option  -  Router Alert \n")
                print("\t\t\tType: 148")
                outputFile.write("\t\t\tType: 148\n")
                Length = int(Trame[off+1], 16)
                print("\t\t\tLength: {}".format(Length))
                outputFile.write("\t\t\tLength: {}\n".format(Length))
                RouterAlert = int(Trame[off+2]+Trame[off+3], 16)
                print("\t\t\tRouter Alert: Router shall examine packet ({})".format(RouterAlert))
                outputFile.write("\t\t\tRouter Alert: Router shall examine packet ({})\n".format(RouterAlert))
                off+=Length
                NmbrOctetsOptions -= Length
            else:
                print("\t\t\t  IP Option non supporté ")    
                outputFile.write("\t\t\t  IP Option non supporté \n")
                Length = int(Trame[off+1], 16)
                off+=Length
                NmbrOctetsOptions -= Length
    if (Protocol == 6):
        
        print_s("Protocole TCP (non supporte !)")

    elif Protocol == 17 : 
        Udp(Trame,int(HeaderLength32)*4)

    else:
        print("   "+Colors.BOLD+Colors.UNDERLINE+"Protocol numéro {} non supporté".format(Protocol)+Colors.ENDC)
        outputFile.write("   Protocol numéro {} non supporté\n".format(Protocol))


def ARP (Trame):
    """Cette fonction analyse le datagramme ARP et ses champs
    Argument : Trame à analyser
    type du Hardware est Ethernet
                 type du protocole est IPVersion4
    """
    print("   "+Colors.BOLD+Colors.UNDERLINE+"Adress Resolution Protocol:"+Colors.ENDC)
    outputFile.write("   Adress Resolution Protocol:\n")
    
    Offset = 14  
    
    Hardware = Trame[Offset]+Trame[Offset+1]
    ProtocolType = Trame[Offset+2]+Trame[Offset+3]
    
    Hardlen = Trame[Offset+4]
    Protlen = Trame[Offset+5]
    
    Oper =  Trame[Offset+6]+Trame[Offset+7]
    
    SenderHardwareAdress =  Trame[Offset+8]+":"+Trame[Offset+9]+":"+Trame[Offset+10]+":"+Trame[Offset+11]+":"+Trame[Offset+12]+":"+Trame[Offset+13]
    SenderProtocolAdress =  ".".join([str(int(oc, 16)) for oc in Trame[Offset+14:Offset+18]])
    TargetHardwareAddress =  Trame[Offset+18]+":"+Trame[Offset+19]+":"+Trame[Offset+20]+":"+Trame[Offset+21]+":"+Trame[Offset+22]+":"+Trame[Offset+23]
    TargetProtocolAdress =  ".".join([str(int(oc, 16)) for oc in Trame[Offset+24:Offset+28]])

    if   int(Hardware,16) == 1:  
        print("\t\tHardware type: Ethernet (1)")
        outputFile.write("\t\tHardware type: Ethernet (1) \n")
        
    if ProtocolType == "0800":
        print("\t\tProtocol type: IPVersion4 (0x0800)") 
        outputFile.write("\t\tProtocol type: IPVersion4 (0x0800)\n")


    print("\t\tHardware size: {}".format(int(Hardlen,16)))
    outputFile.write("\t\tHardware size: {}\n".format(int(Hardlen,16)))

    print("\t\tProtocol size: {}".format(int(Protlen,16)))
    outputFile.write("\t\tProtocol size: {}\n".format(int(Protlen,16)))

    Opercode = {"0001" : "request (1)", "0002" : "reply (2)"}
    print("\t\tOpcode: {}".format(Opercode[Oper]))

    outputFile.write("\t\tOpcode: {}\n".format(Opercode[Oper]))
    print("\t\tSender Hardware address: {}".format(SenderHardwareAdress))

    outputFile.write("\t\tSender Hardware address: {}\n".format(SenderHardwareAdress))
    print("\t\tSender Protocol adress: {}".format(SenderProtocolAdress))

    outputFile.write("\t\tSender Protocol adress: {}\n".format(SenderProtocolAdress))
    print("\t\tTarget Hardware address: {}".format(TargetHardwareAddress))

    outputFile.write("\t\tTarget Hardware address: {}\n".format(TargetHardwareAddress))
    print("\t\tTarget Protocol adress: {}".format(TargetProtocolAdress))
    outputFile.write("\t\tTarget Protocol adress: {}\n".format(TargetProtocolAdress))

#----------------------------------------------------------------------------------------------Couche04: UDP--------------------------------------------------------------------------------------------------------

def Udp (Trm, LongueurIP):
    """Cette fonction analyse le segment UDP affiche ses champs
    Arguments :1)-> Trame à analyser,
    				  2)-> Longueur de l'entete IP
    """
    Off = 14+LongueurIP 

    Srce_port=Trm[Off]+Trm[Off+1]

    Des_port=Trm[Off+2]+Trm[Off+3]
    detect_dns = int(Srce_port,16) == 53 or int(Des_port, 16) == 53
    #si le port source est le port 53, alors le protocole est dns

    Len = Trm[Off+4]+Trm[Off+5]
    Checksum = Trm[Off+6]+Trm[Off+7]

    print("   "+Colors.BOLD+Colors.UNDERLINE+"User Datagram Protocol: (UDP)"+Colors.ENDC)

    print("\t\tSource Port: {}".format(int(Srce_port,16)))
    outputFile.write("\t\tSource Port: {}".format(int(Srce_port,16)))

    print("\t\tDestination Port : {}".format(int(Des_port,16)))
    outputFile.write("\t\tDestination Port : {}".format(int(Des_port,16)))

    print("\t\tLength: {}".format(int(Len,16)))
    outputFile.write("\t\tLength: {}".format(int(Len,16)))

    print("\t\tChecksum:  0x{} [unverified]".format(Checksum))
    outputFile.write("\t\tChecksum:  0x{} [unverified]".format(Checksum))
    if detect_dns :
        dns(Trm, 14 + LongueurIP + 8)


#-------------------------------------------------------------------------------------------------------Couche 07: DNS+DHCP-------------------------------------------------------------------------------------

def dns_resource_record_analysis(trame, count, header_start, offset):
    """Cette fonction analyse un champ resource record de la section dns
    Arguments :1)-> Trame à analyser,
                    2)-> nombre de champs
                        3)-> debut du header
                            4)-> offset actuel
    """
    for i in range(count):
        aname = ""
        print_s("\tResource record "+str(i)+" :")
        is_pointer = hex_to_bin(trame[offset])
        if is_pointer[:2] == "11":
            # we have a pointer to a label
            aname = read_dns_pointer(trame, header_start, offset)
            offset += 2
        else:
            # we just have a label
            dns_name = read_dns_name(trame, header_start, offset)
            aname = dns_name[0]
            offset += dns_name[1]
        atype = trame[offset] + trame[offset+1]
        offset += 2

        aclass = trame[offset] + trame[offset+1]
        offset += 2

        ttl = str(int(trame[offset] + trame[offset+1] + trame[offset+2] + trame[offset+3], 16))
        offset += 4

        rdlength = str(int(trame[offset] + trame[offset+1], 16))
        offset += 2
        rdata = ""
        i = 0
        while i < int(rdlength):
            i += 1
            is_pointer = hex_to_bin(trame[offset])
            is_p = is_pointer[:2]
            if int(trame[offset], 16) == 0:
                rdata += " "
            if is_p == "11" or (is_p == "00" and int(trame[offset]+trame[offset+1], 16)!=0):
                l = read_dns_name(trame, header_start, offset)
                offset += l[1]
                i += l[1]
                rdata += l[0]
            else:
                rdata += "   \n\t"
                for j in range(i, int(rdlength)):
                    if (j-i)%20 == 0 and (j-i)!=0:
                        rdata += "\n\t"
                    rdata += trame[offset]
                    offset += 1
                i = 999999
        
        print_s("\tName : \n\t" + aname)
        print_s("\tType : " + atype)
        print_s("\tClass : " + aclass)
        print_s("\tTTL : "+ttl)
        print_s("\tRdlength : "+rdlength)
        print_s("\tRdata : \n\t"+rdata)

    return offset

def read_dns_pointer(trame, dns_start, offset):
    o = hex_to_bin(trame[offset] + trame[offset+1])
    pointer_offset = int(o[2:], 2) + dns_start
    return read_dns_name(trame, dns_start, pointer_offset)[0]


def read_dns_name(trame, header_start, offset):
    is_pointer = hex_to_bin(trame[offset])
    if is_pointer[:2] == "11":
        # we have a pointer to a label
        aname = read_dns_pointer(trame, header_start, offset)
        return [aname, offset+2]
    c = trame[offset]
    name = ""
    l = 1
    word_len = 0
    while c != '00':
        if word_len == 0:
            word_len = int(c, 16)
            if name != "":
                name += "2e"
        else:
            word_len -= 1
            name += c
        offset += 1
        c = trame[offset]
        l += 1
    n_array = bytes.fromhex(name)
    n_str = n_array.decode()
    return [n_str, l]

def hex_to_bin(byte):
    """Cette fonction traduit UN octet de l'hexadecimal vers le binaire
    Argument : octet en hexa (str),
    Retourne : octet en binaire (str)
    """
    return '{:0>8}'.format(format(int(byte, 16), 'b'))

def print_s(to_print):
    print(to_print)
    outputFile.write(to_print + "\n")

def dns(trame, dns_start):
    """Cette fonction analyse le segment DNS et affiche ses champs
    Argument : 1)-> trame a analyser,
    				  2)-> la position de l'entete dans la trame
    """
    print_s("   "+Colors.BOLD+Colors.UNDERLINE+"Domain Name System : (DNS)"+Colors.ENDC)
    offset = dns_start

    #definition des variables de l'entete dns
    id = "0x" + trame[offset] + trame[offset+1]

    offset += 2
    current_byte = hex_to_bin(trame[offset])
    qr = current_byte[:1]
    opcode_int = int(current_byte[1:5], 2)
    opcode_dict = {0 : "Query", 1 : "Iquery", 2 : "Status"}
    opcode = "NON PRIS EN CHARGE"
    if opcode_int in opcode_dict.keys():
        opcode = opcode_dict[opcode_int]

    aa = current_byte[5:6]

    tc = current_byte[6:7]

    rd = current_byte[7:8]

    offset += 1
    current_byte = hex_to_bin(trame[offset])
    ra = current_byte[:1]

    z = current_byte[1:4]

    rcode_int = int(current_byte[4:8], 2)
    rcode_dict = {0 : "Pas d'erreur", 1 : "Erreur de format de la requete", 
    2 : "Probleme sur serveur", 3 : "Le nom n'existe pas", 4 : "Non implemente",
    5 : "Refus"}
    rcode = "NON PRIS EN CHARGE"
    if rcode_int in rcode_dict.keys():
        rcode = rcode_dict[rcode_int]
    
    offset += 1
    qdcount = int(trame[offset] + trame[offset+1], 16)  #nombre de questions

    offset += 2
    ancount = int(trame[offset] + trame[offset+1], 16)  #nombre de reponses

    offset += 2
    nscount = int(trame[offset] + trame[offset+1], 16)  #nombre de authority

    offset += 2
    arcount = int(trame[offset] + trame[offset+1], 16)  #nombre de resource records

    #affichage de l'entete dns
    print_s("\tIdentification : {}".format(id))
    print_s("\tQr : {}".format(qr))
    print_s("\tOpcode : {}".format(opcode))
    print_s("\tAuthoritative Answer : {}".format(aa))
    print_s("\tTc : {}".format(tc))
    print_s("\tRd : {}".format(rd))
    print_s("\tRa : {}".format(ra))
    print_s("\tZ : {}".format(z))
    print_s("\tRcode : {}".format(rcode))
    print_s("\tQdcount : {}".format(qdcount))
    print_s("\tAncount : {}".format(ancount))
    print_s("\tNscount : {}".format(nscount))
    print_s("\tArcount : {}".format(arcount))

    offset += 2
    #DNS questions :
    print_s("\n\t"+Colors.BOLD+"Questions :"+Colors.ENDC)
    for i in range(qdcount):
        qname = ""
        res_n = read_dns_name(trame, dns_start, offset)
        qname = res_n[0]
        offset += res_n[1]

        qtype = trame[offset] + trame[offset+1]
        offset += 2

        qclass = trame[offset] + trame[offset+1]
        offset += 2
        print_s("\tQname : " + qname)
        print_s("\tQtype : " + qtype)
        print_s("\tQclass : " + qclass)
    
    #DNS answers
    print_s("\n\t"+Colors.BOLD+"Reponses :"+Colors.ENDC)
    old_offset = offset
    offset = dns_resource_record_analysis(trame, ancount, dns_start, offset+0)
    if old_offset == offset :
        print_s("\tNone")

    #authorities
    print_s("\n\t"+Colors.BOLD+"Autorites :"+Colors.ENDC)
    old_offset = offset
    offset = dns_resource_record_analysis(trame, nscount, dns_start, offset)
    if old_offset == offset :
        print_s("\tNone")

    #additionals
    print_s("\n\t"+Colors.BOLD+"Additionnelles :"+Colors.ENDC)
    old_offset = offset
    offset = dns_resource_record_analysis(trame, arcount, dns_start, offset)
    if old_offset == offset :
        print_s("\tNone")

def DHCP(trame,idd):
	file.write("\n\t Message type:\t\t\t")
	if (int(trame[idd],16)==1):
		file.write("Boot Request (1)")
	file.write(str(int(trame[idd],16)))
	idd+=1
	
	file.write("\n\tHardware type :\t\t\t")
	temp=int(trame[idd],16)
	if(temp==1):
		file.write("Ethernet ")
		file.write("("+hex(temp)+")")
	else:
		file.write(temp)
	idd+=1
	
	file.write("\n\t Hardware adress length")
	file.write(str(int(trame[idd],16)))
	idd+=1
	
	temp=""
	for i in trame[idd:idd+4]:
		temp+=i
	file.write("\n\t Transaction ID : \t\t\t")
	file.write(hex(int(temp,16)))
	idd+=4
	
	temp=""
	
	for i in trame[idd:idd+1]:
		temp+=i
	file.write("\n\t Seconde elapsed : \t\t")
	file.write(str(int(temp,16)))
	idd+=2
	temp=""
	for i in trame[idd:idd+2]:
		temp+=i
	file.write("\n\t Bootp flags ;\t\t\t")
	if (int(temp,16)==0):
		file.write(hex(int(temp,16)))
		file.write("      (Unicast")
	else:
		file.write(hex(int(temp,16)))
	idd+=2
	
	file.write("\n\t CLient IP adress : \t\t")
	
	for i in trame[idd:idd+3]:
		file.write(str(int(i)))
		file.write(".")
	file.write(str(int(trame[idd+4],16)))
	idd+=4
	
	file.write("\n\t Tour (Client) IP adress:")
	for i in trame[idd:idd+3]:
		file.write(str(int(i,16)))
		file.write(".")
	file.write(str(int(trame[idd+4],16)))
	idd+=4
	
	file.write("\n\t Next Server IP adress")
	for i in trame[idd:idd+3]:
		file.write(str(int(i,16)))
		file.write(".")
	file.write(str(int(trame[idd+4],16)))
	idd+=4
	
	file.write("\n\t Reply agent IP adress")
	
	for i in trame[idd:idd+3]:
		file.write(str(int(i,16))+".")
	file.write(str(int(trame[idd+4],16)))
	idd+=4
	
	#for i in trame[idd:idd+5]:
		 #file.write(hex(int(i,16))+[2: ]+".")
	#file.write(hex(int(trame[idd+4],16))[2:])
	
	idd+=6
	
	file.write("\n\t Reply agent IP adress")	
	
	for i in trame[idd:idd+10]:
		file.write(str(int(i,16)))
	idd+=10
	
	idd+=64
	
	idd+=128
	
	file.write("\n\t Magic cookie : \t\t\t")
	file.write("DHCP \t\t")
	
	temp= ' '
	
	for i in trame[idd:idd+4]:
		file.write(hex(int(i,16))[2:])
	file.write("0x"+temp)
	idd+=4
	
	file.write("\n\t Next Server IP adress")
		
	file.write("\n\n\t Option + ("+ str(int(trame[idd],16))+")")
	idd+=1
	
	file.write("\n\t\tLength : "+str(int(trame[idd],16)))
	idd+=1
	
	if (int(trame[idd],16)==1):
		file.write("\n\t\t DHCP :Discover (1)")
		
	if (int(trame[idd],16)==2):
		file.write("\n\t\t DHCP :Offer (2)")
			
	if (int(trame[idd],16)==3):
		file.write("\n\t\t DHCP :Request (3)")
		
	if (int(trame[idd],16)==4):
		file.write("\n\t\t DHCP :Decline (4)")
		
	if (int(trame[idd],16)==5):
		file.write("\n\t\t DHCP :ACK (1)")
	
	if (int(trame[idd],16)==6):
		file.write("\n\t\t DHCP :NACK (1)")
	if (int(trame[idd],16)== 7):
		Dname(trame,idd,l)
	
	elif (i==60):
		file.write("\n\t\t\t Vendor class iidentifier : ")
		Dname(trame,idd,l)
	elif (i==1):
		file.write("\n\t\t\t Subnet MASK : ")
		IPDHCP(trame,idd,l)
	elif (i==2):
		file.write("\n\t\t\t Routeur : ")
		IPDHCP(trame,idd,l)
	elif (i==6):
		file.write("\n\t\t\t DNS : ")
		IPDHCP(trame,idd,l-4)
		
		file.write("\n\t\t\t DNS : ")
		IPDHCP(trame,idd+4,l-4)
		
	elif (i==15):
		file.write("\n\t\t\t Domain name : ")
		Dname(trame,idd,l-1)
	elif (i==51):
		file.write("\n\t\t\t Adress lease time : ")
		temp=' '
		for i in trame[idd:idd+1]:
			temp+=0
		file.write("("+str(int(temp,16))+"s)")
	elif (i==54):
		file.write("\n\t\t\t DHCP SERVER Identifier : ")
		IPDHCP(trame,idc,l)
		
		
	else:
		file.write("\n\t\t Option DHCP Non traiter")	
		
		
	if (int(trame[idd],16)==6):
		file.write("\n\t\t DHCP :NACK (6)")
	if (int(trame[idd],16)==7):
		file.write("\n\t\t DHCP :Release (5)")
	if (int(trame[idd],16)==8):
		file.write("\n\t\t DHCP :inform (5)")
	idd+=1
	file.write("\n")
	
	while(str(trame[idd]) != 'ff'):
		file.write("\n\t\t Option : ("+str(int(trame[idd],16))+")")
		
		i=int(trame[idd],16)
		idd+=1
	
		file.write("\n\t\t Length : "+str(int(trame[idd],16)))
		
		l=int(trame[idd],16)
		idd+=1
		
		if (i==116):
			file.write("\n\t\t\t DHCP Auto Configuration :Auto Configure (1)")
			
def DName(trame,idd,l):
	temp =' '
	for i in trame[idd:idd+i]:
		temp+=i
		
	hx=bytes.fromhex(temp)
	hx.decode("ASCII")
	hx=hx[:len(hx)]
	file.write(str(hx))

def IPDHCP(trame,idd,l):
	for i in trame[idd:idd+i-1]:
		file.write(str(int(i,16)))
		file.write(" . ")
	file.write(str(int(trame[idd+(l-1)],16)))
	file.write("\n")
	
	return idd+l
	
def MACDHCP(trame,idd,l):
	for i in trame[idd:idd+l-1]:
		file.write(str(int(i,16)))
		file.write(" : ")
	file.write(str(int(trame[idd+(l-1)],16)))
	file.write("\n")
	return idd+l
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	


class Colors:
	OKGREEN = '\033[92m'
	UNDERLINE = '\033[4m'
	WARNING = '\033[93m'
	FAIL = '\033[91m'
	BOLD = '\033[1m'
	ENDC = '\033[0m'

outputFile = open("ResAnalys.txt", "w")

def main():
    while True:
        NomFichier = input(Colors.BOLD+"Entrer le nom du fichier qui contient la(les) Trame(s) : "+Colors.ENDC)
        try:
            file = open(NomFichier)
        except:
            print("Fichier non existant !! ")
        else:
            break
    outputFile.write("Trame(s) extraite(s) du fichier : "+NomFichier+"\n")
    Dico = FichierParse(file)
    Layers(Dico)
    outputFile.close()



if __name__ == "__main__":
    main()






