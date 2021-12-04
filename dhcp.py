def dhcp(dhcp):
    typ=''
    print("DHCP Type:",typ)
    op= int(dhcp[0:2],16)
    if(op==1):
        print("requête client")
    elif(op==2):
        print("réponse serveur")
    else:
        print("pa d'opération!")
    htype=int(dhcp[2:4],16)
    htypehex=hex(htype)
    if (htype==1):
        print("type de l'adresse hardware est: Mac Ethernet")
    else:
        print("type de l'adresse hardware",htype,"(",htypehex,")")
    hlen=int(dhcp[4:6],16)
    hlenhex=hex(hlen)
    print('la longueur de l'/'adresse hardware est:', hlen,"(",hlenhex,")")
    hops=int(dhcp[6:8],16)
    if(hops!=0):
        print('utilisé par un(des) relais',hops)
    else:
        print('non utilisé par des relais',hops)
    transid=int(dhcp[8:16],16)
    transhex=hex(transid)
    print('l'/'idebtifiant d client pour la transation(numéro aléatoire choisi par le client pour être reconnu est: )',transid,"(",transhex,")")
    secs=int(dhcp[16:20],16)
    secshex=hex(secs)
    print('Le temps écoulé par le client est de',secs,'(',secshex,') depuis que la client a commencé sa requête')
    flags=int(dhcp[20:24])
    if (flags==1):
        print('inducateur de broadcast')
    else:
        print('indicateurs diverses: ', flags)
    ciaddr=" "+str(int(dhcp[24:26],16))+"."+str(int(dhcp[26:28],16))+"."+str(int(dhcp[28:30],16))+"."+str(int(dhcp[30:32],16))
    if(ciaddr!='0.0.0.0'):
        print('le client a déja une adresse (ciaddr) qui est: ',ciaddr)
    else:
        print('le client n'/'a pas d'/'adresse ip, doit être assigner l'/'adresse 0.0.0.0')
    yiaddr=" "+str(int(dhcp[32:34],16))+"."+str(int(dhcp[34:36],16))+"."+str(int(dhcp[36:38],16))+"."+str(int(dhcp[38:40],16))
    print('la future adresse du client est(yiddr): ',yiaddr) 
    siaddr=" "+str(int(dhcp[40:42],16))+"."+str(int(dhcp[42:44],16))+"."+str(int(dhcp[44:46],16))+"."+str(int(dhcp[46:48],16))
    print('l'/'adresse Ip du prochaint serveur (siaddr) à utiliserest: ',siaddr)
    giaddr=" "+str(int(dhcp[48:50],16))+"."+str(int(dhcp[50:52],16))+"."+str(int(dhcp[52:54],16))+"."+str(int(dhcp[54:56],16))  
    print('l'/'adresse du relais ou la passerelle (giaddr)si la connexion direte n'/'est pas possible est: ',giaddr)
    chaddr=" "+str(hex(dhcp[56:58]))+":"+str(hex(dhcp[58:60]))+":"+str(hex(dhcp[60:62]))+":"+str(hex(dhcp[62:64]))+":"+str(hex(dhcp[64:66])+":"+str(hex(dhcp[64:68])))
    print('l'/'adresse mac(hardwre) du client (chaddr)est: ',chaddr)
    sname=str(dhcp[68:132])
    print('le nom du serveur est: ',sname)
    fichier=str(dhcp[132:260])
    print('le fichier du boot est: ',fichier)

    return