# Projet_reseaux:

#-----------------------------------------------------------------------------------------------------------Fichier Parse---------------------------------------------------------------------------------------------
def FichierParse (file):
    """FichierParse lit le fichier à analyser.
    Arg :  fichier dans le meme repertoire.
    Retourne : un dictionnaire des trames correctes et de trames erronees et les lignes qui sont fausses dans les trames erronees .
    
    """
    OffsetCourant = 0

    Lignes = file.readlines()

    LignesValides, PositionLignes = [], {}
    

    for ind in range(len(Lignes)):

        Ligne = Lignes[ind].strip().lower()
        

        if Ligne :
            Offset = Ligne.split(maxsplit=1)[0] 																						
        else:
            Offset = ""

        if OffsetValide(Offset, OffsetCourant):
            OffsetCourant = int(Offset, 16)
            PositionLignes[Ligne] = ind
            LignesValides.append(Ligne) 																								
        else:
            print("Ligne removed  :  ", Lignes[ind])

    TramesCorrectes = []
    TramesErronees = []
    ListeLignesErronees = []

    for ind in range(len(LignesValides)):

        OffsetCourant = int(LignesValides[ind].split(maxsplit=1)[0], 16)
        if ind+1 == len(LignesValides) : 
            OffsetSuivant = 0
        else:
            OffsetSuivant = int(LignesValides[ind+1].split(maxsplit=1)[0], 16)

        if OffsetCourant == 0:
            Trame = []
            trameValidee = True
        
        splittedLine = LignesValides[ind].split()

        if OffsetSuivant != 0 :
            NmbrOctetsSurLaLigne = OffsetSuivant - OffsetCourant

            if SequenceOctetValide(splittedLine[1:], NmbrOctetsSurLaLigne) : 
                Trame.extend(splittedLine[1:NmbrOctetsSurLaLigne+1])
            else:
                ListeLignesErronees.append(PositionLignes[LignesValides[ind]])
                trameValidee = False
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
                            trameValidee = False
                            ListeLignesErronees.append(PositionLignes[LignesValides[ind]])
                            print("Champs longueur totale du datagramme IP errone ligne erronée : n°", PositionLignes[LignesValides[ind]])
            NmbrOctetsSurLaLigne = LongueurTrame + 14 - len(Trame)     									#LongueurTrame représente la longueur totale de la Trame
                                                                    																			     
            if SequenceOctetValide(splittedLine[1:], NmbrOctetsSurLaLigne) :
                print(splittedLine[1:NmbrOctetsSurLaLigne+1])
                Trame.extend(splittedLine[1:NmbrOctetsSurLaLigne+1])
            else:
                trameValidee = False
                ListeLignesErronees.append(PositionLignes[LignesValides[ind]])

            if trameValidee :
                TramesCorrectes.append(Trame)
            else:
                TramesErronees.append(Trame)

    return {"trames correctes" : TramesCorrectes,
            "trames erronees" : TramesErronees,
            "lignes erronees" : ListeLignesErronees,
            }

#----------------------------------------------------------------------------------------------------------------Ethernet----------------------------------------------------------------------------------------------

def Ethernet (Trame) : 
    """Cette fonction analyse la Trame Ethernet  et affiche ses champs 
    Argument : Trame à analyser
    """
    TypeDeProtocol = {"0800": "IPVersion4", "080": " ", "0806" : "ARP"}
    
    AdrDestination = Trame[0]+":"+Trame[1]+":"+Trame[2]+":"+Trame[3]+":"+Trame[4]+":"+Trame[5]
    AdrSource = Trame[6]+":"+Trame[7]+":"+Trame[8]+":"+Trame[9]+":"+Trame[10]+":"+Trame[11]
    
    typee = Trame[12]+Trame[13]
    
    print_s("   "+Colors.BOLD+Colors.UNDERLINE+"Protocol Ethernet:"+Colors.ENDC)
    print_s("\tDestination: {}".format(AdrDestination))
    print_s("\tSource: {}".format(AdrSource))

    if(typee in TypeDeProtocol.keys()):
    
        print_s("\tType: {} (0x{}) ".format(TypeDeProtocol[typee], typee))
    
   
    if typee == "0800":
        IPVersion4(Trame)
    
    elif typee == "0806":
        ARP(Trame)
    
    else :
        print_s(Colors.WARNING+Colors.BOLD+"  Protocol n°{} (non supporte !)".format(typee)+Colors.ENDC)

def Layers (Dico):
    
    Trames = Dico["trames correctes"]
    NmbrTrames = len(Trames)
    
    print_s(Colors.FAIL+Colors.BOLD+"Trames erronees : " + str(len(Dico["trames erronees"])) + Colors.ENDC)

    for ligne in Dico["lignes erronees"]:
        print_s("\tLigne {} erronnee".format(ligne))

    print_s(Colors.OKGREEN+Colors.BOLD+"Trame(s) correcte(s) : "+ str(NmbrTrames)+ Colors.ENDC+"\n")

    for Trame, i  in zip(Trames, range(len(Trames))) :
        print_s(Colors.WARNING+"Trame {} : ({} octets)".format(i, len(Trame))+Colors.ENDC)
        try :
            Ethernet(Trame)
        except Exception as excep:
            if hasattr(excep, 'message'):
                print(excep.message)
            else:
                print(excep)
            
        print_s("\n")

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
    






#------------------------------------------------------------------------------------------------------Couches 3: IP+ ARP------------------------------------------------------------------------------------------

def IPVersion4(Trame):
    """Cette fonction analyse le datagramme IP version 4  affiche ses champs
    Argument : Trame à analyser
    """
    
    Offset = 14                                                                                
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
    FragmentOffset = PremierByte[3:]+DeuxiemeByte

    Ttl = Trame[Offset+8]
    Protocol = int(Trame[Offset+9], 16)
    
    HeaderChecksum =Trame[Offset+10]+Trame[Offset+11]
    
    Srce_addr= '.'.join([str(int(x,16)) for x in Trame[Offset+12:Offset+16]])
    Des_addr='.'.join([str(int(x,16)) for x in Trame[Offset+16:Offset+20]])
    
    OptionsTypee = 1

    print_s("   "+Colors.BOLD+Colors.UNDERLINE+"Internet Protocol Version 4:"+Colors.ENDC)
    print_s("\t{} .... = Version: 4 ".format(format(int(Version, 16), '04b')))
    print_s("\t.... {} = Header Length: {} bytes ({}) ".format(format(int(str(HeaderLength32), 16), '04b'),int(str(HeaderLength32),16)*4,HeaderLength32))
    print_s("\tIdentification: 0x{} ({})".format(Id,int(Id,16)))

    Dic_not_set={"0":"Not set","1":"Set"}

    print_s("\tFlags: 0x{} ".format(Trame[Offset+6]))
    print_s("\t\t{}... .... = Reserved bit: {} ".format(ReservedBit,Dic_not_set[ReservedBit]))
    print_s("\t\t.{}.. .... = Don't fragment: {} ".format(DFragment,Dic_not_set[DFragment]))
    print_s("\t\t..{}. .... = More fragments: {} ".format(MFragment,Dic_not_set[MFragment]))
    print_s("\tTotal Length: {}".format(int(TotalLength,16)))
    print_s("\tTime to Live: {}".format(int(Ttl,16)))

    if(Protocol in Protocols.keys()):
        print_s("\tProtocol: {} ({})".format(Protocols[Protocol],Protocol))

    print_s("\tHeader Checksum: 0x{}".format(HeaderChecksum))
    print_s("\tSource Address: {}".format(Srce_addr))
    print_s("\tDestination Address: {}".format(Des_addr))

#-----------------------------------------------------------------------------------------------------OPTIONS IP-----------------------------------------------------------------------------------------------------

    
    if (HeaderLength32 > 5):                             

        NmbrOctetsOptions = (HeaderLength32 - 5) * 4
        print_s("\tOptions: {} bytes".format(NmbrOctetsOptions))

        off = Offset+20

        while True : 
            if NmbrOctetsOptions == 0 : 
                break
            PremierOctetOption = Trame[off]              

            if (int(PremierOctetOption, 16) == 0):
                print_s("\t  IP Option  -  End of Options List (EOL)")
                print_s("\t\tType: 0")
                off+=1
                NmbrOctetsOptions -=1
            elif (int(PremierOctetOption, 16) == 1):
                print_s("\t  IP Option  -  No Operation (NOP)")
                print_s("\t\tType: 1")
                off+=1
                NmbrOctetsOptions -=1
            elif (int(PremierOctetOption, 16) == 7):
                print_s("\t  IP Option  -  Record Route (RR)")

                print_s("\t\tType: 7")

                Length = int(Trame[off+1], 16)
                print_s("\t\tLength: {}".format(Length))

                Pointer = int(Trame[off+2], 16)

                print_s("\t\tPointer: {}".format(Pointer))

                for i in range((Length-3)//4):
                    RR= '.'.join([str(int(x,16)) for x in Trame[off+3+i*4:off+7+i*4]])
                    print_s("\t\tRecorded Route: {}".format(RR))
                
                off+=Length
                NmbrOctetsOptions -= Length

            elif (int(PremierOctetOption, 16) == 131):
                print_s("\t  IP Option  -  Loose Source Route (LSR)")

                print_s("\t\tType: 131")

                Length = int(Trame[off+1], 16)
                print_s("\t\tLength: {}".format(Length))
                Pointer = int(Trame[off+2], 16)

                print_s("\t\tPointer: {}".format(Pointer))

                for i in range((Length-3)//4):
                    Route= '.'.join([str(int(x,16)) for x in Trame[off+3+i*4:off+7+i*4]])
                    print_s("\t\tRoute: {}".format(Route)) 
                off+=Length
                NmbrOctetsOptions -= Length

            elif (int(PremierOctetOption, 16) == 137):
                print_s("\t  IP Option  -  Strict Source Route (SSR)")

                print_s("\t\tType: 137")
                Length = int(Trame[off+1], 16)

                print_s("\t\tLength: {}".format(Length))
                Pointer = int(Trame[off+2], 16)

                print_s("\t\tPointer: {}".format(Pointer))

                for i in range((Length-3)//4):
                    Route= '.'.join([str(int(x,16)) for x in Trame[off+3+i*4:off+7+i*4]])
                    print_s("\t\tRoute: {}".format(Route)) 
                off+=Length
                NmbrOctetsOptions -= Length

            elif (int(PremierOctetOption, 16) == 148):
                print_s("\t  IP Option  -  Router Alert ")
                print_s("\t\tType: 148")
                Length = int(Trame[off+1], 16)
                print_s("\t\tLength: {}".format(Length))
                RouterAlert = int(Trame[off+2]+Trame[off+3], 16)
                print_s("\t\tRouter Alert: Router shall examine packet ({})".format(RouterAlert))
                off+=Length
                NmbrOctetsOptions -= Length
            else:
                print_s("\t  IP Option non supporte ! ")
                Length = int(Trame[off+1], 16)
                off+=Length
                NmbrOctetsOptions -= Length
    if (Protocol == 6):
        
        print_s("Protocole TCP (non supporte !)")

    elif Protocol == 17 : 
        Udp(Trame,int(HeaderLength32)*4)

    else:
        print_s("   "+Colors.BOLD+Colors.UNDERLINE+"Protocol n°{} non supporte".format(Protocol)+Colors.ENDC)

def ARP (Trm):
    """Cette fonction analyse le datagramme ARP et ses champs
    Argument : Trame à analyser
    type du Hardware est Ethernet
                 type du protocole est IPVersion4
    """
    print_s("   "+Colors.BOLD+Colors.UNDERLINE+"Adress Resolution Protocol:"+Colors.ENDC)
    
    Offset = 14  
    
    Hardware = Trm[Offset]+Trm[Offset+1]
    ProtocolType = Trm[Offset+2]+Trm[Offset+3]
    Hardlen = Trm[Offset+4]
    Protlen = Trm[Offset+5]
    
    Oper =  Trm[Offset+6]+Trm[Offset+7]
    
    SenderHardwareAdress =  Trm[Offset+8]+":"+Trm[Offset+9]+":"+Trm[Offset+10]+":"+Trm[Offset+11]+":"+Trm[Offset+12]+":"+Trm[Offset+13]
    SenderProtocolAdress =  ".".join([str(int(oc, 16)) for oc in Trm[Offset+14:Offset+18]])
    TargetHardwareAddress =  Trm[Offset+18]+":"+Trm[Offset+19]+":"+Trm[Offset+20]+":"+Trm[Offset+21]+":"+Trm[Offset+22]+":"+Trm[Offset+23]
    TargetProtocolAdress =  ".".join([str(int(oc, 16)) for oc in Trm[Offset+24:Offset+28]])

    if   int(Hardware,16) == 1:  
        print_s("\tHardware type: Ethernet (1)")
        
    if ProtocolType == "0800":
        print_s("\tProtocol type: IPVersion4 (0x0800)") 


    print_s("\tHardware size: {}".format(int(Hardlen,16)))

    print_s("\tProtocol size: {}".format(int(Protlen,16)))

    Opcode = {"0001" : "request (1)", "0002" : "reply (2)"}
    print_s("\tOpcode: {}".format(Opcode[Oper]))

    print_s("\tSender Hardware address: {}".format(SenderHardwareAdress))

    print_s("\tSender Protocol adress: {}".format(SenderProtocolAdress))

    print_s("\tTarget Hardware address: {}".format(TargetHardwareAddress))

    print_s("\tTarget Protocol adress: {}".format(TargetProtocolAdress))


#----------------------------------------------------------------------------------------------Couche04: UDP--------------------------------------------------------------------------------------------------------

def Udp (Trm, LongueurIP):
    """Cette fonction analyse le segment UDP affiche ses champs
    Arguments :1)-> Trame à analyser,
    				  2)-> Longueur de l'entete IP
    """
    Offset = 14+LongueurIP 

    Source_port=Trm[Offset]+Trm[Offset+1]

    Dest_port=Trm[Offset+2]+Trm[Offset+3]
    detect_dns = int(Source_port,16) == 53 or int(Dest_port, 16) == 53
    #si le port source est le port 53, alors le protocole utlise est dns
    detect_dhcp = int(Source_port,16) == 67  or int(Dest_port, 16) == 67
    #si le port source est le port 67, alors le protocole utlise est dhcp

    Length = Trm[Offset+4]+Trm[Offset+5]
    Checksum = Trm[Offset+6]+Trm[Offset+7]

    print_s("   "+Colors.BOLD+Colors.UNDERLINE+"User Datagram Protocol: (UDP)"+Colors.ENDC)

    print_s("\tSource port: {}".format(int(Source_port,16)))

    print_s("\tDestination port : {}".format(int(Dest_port,16)))

    print_s("\tLength: {}".format(int(Length,16)))

    print_s("\tChecksum: 0x{}".format(Checksum))
    if detect_dns :
        dns(Trm, 14 + LongueurIP + 8)
    if detect_dhcp:
        DHCP(Trm, 14 + LongueurIP + 8)

#--------------------------------------------------------------------------------------------------Couche 07: DNS--------------------------------------------------------------------------------------------------

def DHCP(trame,idd):
    print_s("   "+Colors.BOLD+Colors.UNDERLINE+"Dynamic Host Configuration Protocol : (DHCP)"+Colors.ENDC)

    to_print = "???"
    if (int(trame[idd],16)==1):
	    to_print = "Boot Request"
    print_s("\t Message type (" + str(int(trame[idd],16)) + ") : " + to_print)
    idd+=1

	
    
    temp=int(trame[idd],16)
    to_print = ""
    if(temp==1):
        to_print = "Ethernet "
        to_print = ""+hex(temp)+""
    print_s("\t Hardware type : " + to_print)
    idd+=1
	
    print_s("\t Hardware adress length : " + str(int(trame[idd],16)))
    idd+=1
	
    temp=""
    for i in trame[idd:idd+4]:
        temp+=i
    print_s("\t Transaction ID : " + hex(int(temp,16)))
    idd+=4
	
    temp=""
	
    for i in trame[idd:idd+1]:
        temp+=i
    print_s("\t Seconds elapsed : " + str(int(temp,16)))
    idd+=2
    temp=""
    for i in trame[idd:idd+2]:
        temp+=i
    to_print = ""
    if (int(temp,16)==0):
        to_print = hex(int(temp,16)) + "      (Unicast"
    else:
        to_print = hex(int(temp,16))
    print_s("\t Bootp flags : "+to_print)
    idd+=2
	
    to_print = ""
    for i in trame[idd:idd+3]:
        to_print += (str(int(i))) + "."
    print_s("\t CLient IP adress : " + to_print + str(int(trame[idd+4],16)))
    idd+=4
	
    to_print = ""
    for i in trame[idd:idd+3]:
        to_print += (str(int(i,16)))
        to_print += (".")
    to_print += (str(int(trame[idd+4],16)))
    print_s("\t Your (Client) IP adress : " + to_print)
    idd+=4
	
    to_print = ""
    for i in trame[idd:idd+3]:
        to_print += (str(int(i,16)))
        to_print += (".")
    to_print += (str(int(trame[idd+4],16)))
    print_s("\t Next Server IP adress : " + to_print)
    idd+=4
	
    to_print = ""
    for i in trame[idd:idd+3]:
        to_print += str(int(i,16))+"."
    to_print += str(int(trame[idd+4],16))
    print_s("\t Relay agent IP adress : " + to_print)
    idd+=4
	
    """to_print = ""
    for i in trame[idd:idd+5]:
        to_print += hex(int(i,16))
        for j in trame[2:]:
            to_print += j
        to_print += "."
    to_print += (hex(int(trame[idd+4],16))[2:])
    print_s(to_print)"""

    idd+=6
    to_print = ""
    for i in trame[idd:idd+10]:
        to_print += str(int(i,16))
    print_s("\t Reply agent IP adress : " + to_print)	
    idd+=10
	
    idd+=64
	
    idd+=128
	
    temp= ' '
    to_print = ""
    for i in trame[idd:idd+4]:
        to_print += hex(int(i,16))[2:]
    to_print = "0x" + to_print +temp
    print_s("\t Magic cookie : DHCP : "+to_print)
    idd+=4
		
    print_s("\n\t Option + ("+ str(int(trame[idd],16))+")")
    idd+=1
	
    print_s("\t\tLength : "+str(int(trame[idd],16)))
    idd+=1
	
    if (int(trame[idd],16)==1):
        print_s("\t\t DHCP :Discover (1)")
		
    if (int(trame[idd],16)==2):
        print_s("\n\t\t DHCP :Offer (2)")
			
    if (int(trame[idd],16)==3):
        print_s("\t\t DHCP :Request (3)")
		
    if (int(trame[idd],16)==4):
        print_s("\t\t DHCP :Decline (4)")
		
    if (int(trame[idd],16)==5):
        print_s("\t\t DHCP :ACK (1)")
	
    if (int(trame[idd],16)==6):
        print_s("\t\t DHCP :NACK (1)")
    if (int(trame[idd],16)== 7):
        Dname(trame,idd,l)
	
    elif (i==60):
        print_s("\t\t\t Vendor class iidentifier : ")
        Dname(trame,idd,l)
    elif (i==1):
        print_s("\t\t\t Subnet MASK : ")
        IPDHCP(trame,idd,l)
    elif (i==2):
        print_s("\t\t\t Routeur : ")
        IPDHCP(trame,idd,l)
    elif (i==6):
        print_s("\t\t\t DNS : ")
        IPDHCP(trame,idd,l-4)
        print_s("\t\t\t DNS : ")
        IPDHCP(trame,idd+4,l-4)
    elif (i==15):
        print_s("\t\t\t Domain name : ")
        Dname(trame,idd,l-1)
    elif (i==51):
        print_s("\t\t\t Adress lease time : ")
        temp=' '
        for i in trame[idd:idd+1]:
            temp+=0
        print_s("("+str(int(temp,16))+"s)")
    elif (i==54):
        print_s("\t\t\t DHCP SERVER Identifier : ")
        IPDHCP(trame,idd,l)
    else:
        print_s("\t\t Option DHCP Non traite")	
    if (int(trame[idd],16)==6):
        print_s("\t\t DHCP :NACK (6)")
    if (int(trame[idd],16)==7):
        print_s("\t\t DHCP :Release (5)")
    if (int(trame[idd],16)==8):
        print_s("\t\t DHCP :inform (5)")
    idd+=1
    
    while(str(trame[idd]) != 'ff'):
        print_s("\t\t Option : "+str(int(trame[idd],16)))
        i=int(trame[idd],16)
        idd+=1
        if int(trame[idd],16) == 255:
            print_s("\t End of options list")
            break
        print_s("\t\t Length : "+str(int(trame[idd],16)))
		
        l=int(trame[idd],16)
        idd+=1
		
        if (i==116):
            print_s("\t\t\t DHCP Auto Configuration :Auto Configure (1)")
			
def DName(trame,idd,l):
    temp =' '
    for i in trame[idd:idd+i]:
        temp+=i
		
    hx=bytes.fromhex(temp)
    hx.decode("ASCII")
    hx=hx[:len(hx)]
    print_s(str(hx))

def IPDHCP(trame,idd,l):
    to_print = ""
    for i in trame[idd:idd+i-1]:
        to_print += (str(int(i,16)))
        to_print += (" . ")
    print_s(to_print + " " + str(int(trame[idd+(l-1)],16)))
    return idd+l
	
def MACDHCP(trame,idd,l):
	for i in trame[idd:idd+l-1]:
		print_s(str(int(i,16)))
		print_s(" : ")
	print_s(str(int(trame[idd+(l-1)],16)))
	return idd+l
	
#-----------------------------------------------------------------------------------------------------Couche 07: DNS-----------------------------------------------------------------------------------------------

def dns_resource_record_analysis(trame, count, header_start, offset):
    """Cette fonction analyse un champ resource record de la section dns
    Arguments :1)-> Trame à analyser,
                    2)-> nombre de champs
                        3)-> debut du header
                            4)-> offset actuel
    """
    for i in range(count):
        aname = ""
        print_s("\tResource record "+str(i+1)+" :")
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
        type_dict = {
            1   : "A",
            28  : "AAAA",
            38  : "A6",
            18  : "AFSDB",
            5   : "CNAME",
            39  : "DNAME",
            48  : "DNSKEY",
            43  : "DS",
            108 : "EUI48",
            109 : "EUI64",
            13  : "HINFO",
            20  : "ISDN",
            25  : "KEY",
            29  : "LOC",
            15  : "MX",
            35  : "NAPTR",
            2   : "NS",
            47  : "NSEC",
            30  : "NXT",
            12  : "PTR",
            17  : "RP",
            46  : "RRSIG",
            21  : "RT",
            24  : "SIG",
            6   : "SOA",
            99  : "SPF",
            33  : "SRV",
            16  : "TXT",
            256 : "URI",
            11  : "WKS",
            19  : "X25"
        }
        atype_val = "???"
        if (int(trame[offset] + trame[offset+1], 16)) in type_dict.keys():
            atype_val = type_dict[int(trame[offset] + trame[offset+1], 16)]
        atype = trame[offset] + trame[offset+1] + " (" + atype_val + ")"
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
            if is_p == "11" or (is_p == "00" and int(trame[offset]+trame[offset+1], 16)!=0):
                l = read_dns_name(trame, header_start, offset)
                offset += l[1]
                i += l[1]-1
                rdata += l[0]
                if l[1] != "":
                    rdata += " "
            else:
                rdata += "   \n\t    "
                for j in range(i, int(rdlength)+1):
                    if (j-i)%20 == 0 and (j-i)!=0:
                        rdata += "\n\t    "
                    rdata += trame[offset] + " "
                    offset += 1
                i = 999999
        
        print_s("\t  Name : " + aname)
        print_s("\t  Type : 0x" + atype)
        print_s("\t  Class : 0x" + aclass)
        print_s("\t  TTL : "+ttl+" seconds")
        print_s("\t  Data length : "+rdlength)
        print_s("\t  Rdata : "+rdata)

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
    for c in [Colors.OKGREEN, Colors.UNDERLINE, Colors.WARNING, Colors.FAIL, Colors.BOLD, Colors.ENDC]:
        to_print = to_print.replace(c, "")
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




class Colors:
	OKGREEN = '\033[92m'
	UNDERLINE = '\033[4m'
	WARNING = '\033[93m'
	FAIL = '\033[91m'
	BOLD = '\033[1m'
	ENDC = '\033[0m'

outputFile = open("resultatAnalyseur.txt", "w")

#---------------------------------------------------------------------------------------------------main---------------------------------------------------------------------------------------------------------------

def main():
    while True:
        NomFichier = input(Colors.BOLD+"Entrer le nom du fichier contenant la(les) Trame(s) : "+Colors.ENDC)
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






