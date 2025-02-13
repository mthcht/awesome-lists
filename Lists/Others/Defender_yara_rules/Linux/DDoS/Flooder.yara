rule DDoS_Linux_Flooder_A_2147766302_0
{
    meta:
        author = "defender2yara"
        detection_name = "DDoS:Linux/Flooder.A!MTB"
        threat_id = "2147766302"
        type = "DDoS"
        platform = "Linux: Linux platform"
        family = "Flooder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "python ddos.py -u <ip> <port>" ascii //weight: 1
        $x_1_2 = "cb_udp_ddos_script" ascii //weight: 1
        $x_1_3 = "Run UDP Basic Attack" ascii //weight: 1
        $x_1_4 = "flood_dns" ascii //weight: 1
        $x_1_5 = "cb_chargen_ddos" ascii //weight: 1
        $x_1_6 = "thread_attack" ascii //weight: 1
        $x_1_7 = "flood_vse" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule DDoS_Linux_Flooder_Dx_2147795744_0
{
    meta:
        author = "defender2yara"
        detection_name = "DDoS:Linux/Flooder.Dx!xp"
        threat_id = "2147795744"
        type = "DDoS"
        platform = "Linux: Linux platform"
        family = "Flooder"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Spoofed UDP Flooder" ascii //weight: 1
        $x_1_2 = "Starting Flood" ascii //weight: 1
        $x_1_3 = "myStrCat" ascii //weight: 1
        $x_1_4 = "sudp.c" ascii //weight: 1
        $x_1_5 = "<target IP/hostname> <port to be flooded> " ascii //weight: 1
        $x_1_6 = "rand_cmwc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule DDoS_Linux_Flooder_SB_2147808336_0
{
    meta:
        author = "defender2yara"
        detection_name = "DDoS:Linux/Flooder.SB!xp"
        threat_id = "2147808336"
        type = "DDoS"
        platform = "Linux: Linux platform"
        family = "Flooder"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Starting Flood..." ascii //weight: 2
        $x_2_2 = "Opening sockets..." ascii //weight: 2
        $x_2_3 = "Sending attack..." ascii //weight: 2
        $x_2_4 = "Setting up Sockets..." ascii //weight: 2
        $x_2_5 = "Usage: %s <target" ascii //weight: 2
        $x_2_6 = "Usage: %s <IP> <threads>" ascii //weight: 2
        $x_2_7 = ":: sending all the packets.." ascii //weight: 2
        $x_2_8 = ":: cant open raw socket. got root" ascii //weight: 2
        $x_2_9 = ":: motherfucking error." ascii //weight: 2
        $x_2_10 = "Flooding %s" ascii //weight: 2
        $x_2_11 = "UDP Flooder v1.2.8 FINAL by ohnoes1479" ascii //weight: 2
        $x_2_12 = "Sending packets.." ascii //weight: 2
        $x_2_13 = "Opening threads..." ascii //weight: 2
        $x_2_14 = "Usage: %s [IP]" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule DDoS_Linux_Flooder_H_2147813587_0
{
    meta:
        author = "defender2yara"
        detection_name = "DDoS:Linux/Flooder.H!xp"
        threat_id = "2147813587"
        type = "DDoS"
        platform = "Linux: Linux platform"
        family = "Flooder"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Flooding IP: %s | PORT: %d  | BY MORGAN" ascii //weight: 1
        $x_1_2 = {55 73 61 67 65 3a 20 25 73 [0-21] 5b 4c 49 53 54 2e 54 58 54 5d [0-21] 5b 54 49 4d 45 5d}  //weight: 1, accuracy: Low
        $x_1_3 = "MSSQL By MORGAN" ascii //weight: 1
        $x_1_4 = "mssql.c" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule DDoS_Linux_Flooder_K_2147813589_0
{
    meta:
        author = "defender2yara"
        detection_name = "DDoS:Linux/Flooder.K!xp"
        threat_id = "2147813589"
        type = "DDoS"
        platform = "Linux: Linux platform"
        family = "Flooder"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "tcpcsum" ascii //weight: 2
        $x_2_2 = "floodport" ascii //weight: 2
        $x_1_3 = "fruitstresser" ascii //weight: 1
        $x_1_4 = "STARTING ATTACK..." ascii //weight: 1
        $x_1_5 = "starting DDoS..." ascii //weight: 1
        $x_1_6 = "SETTING SOCKETS..." ascii //weight: 1
        $x_1_7 = "khaos.c" ascii //weight: 1
        $x_1_8 = "Setting up Sockets..." ascii //weight: 1
        $x_1_9 = "Destroy that fucking bitch" ascii //weight: 1
        $x_1_10 = "Attack Started..." ascii //weight: 1
        $x_1_11 = "MyGameArea UDP Spoof Flood Script" ascii //weight: 1
        $x_1_12 = "%s IP PORT 10-50 TIMES" ascii //weight: 1
        $x_1_13 = "Starting destroying..." ascii //weight: 1
        $x_1_14 = "Starting Flood..." ascii //weight: 1
        $x_1_15 = "%s {target IP} {threads}" ascii //weight: 1
        $x_1_16 = "%s [ip] [port]" ascii //weight: 1
        $x_1_17 = "Saldiri Basladi" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule DDoS_Linux_Flooder_L_2147813593_0
{
    meta:
        author = "defender2yara"
        detection_name = "DDoS:Linux/Flooder.L!xp"
        threat_id = "2147813593"
        type = "DDoS"
        platform = "Linux: Linux platform"
        family = "Flooder"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "udpFlood" ascii //weight: 2
        $x_2_2 = "addUDP" ascii //weight: 2
        $x_1_3 = "Infecteur.c" ascii //weight: 1
        $x_1_4 = "synAttack" ascii //weight: 1
        $x_1_5 = "Infecteur udp_flood" ascii //weight: 1
        $x_1_6 = {75 73 61 67 65 3a 20 2e 2f 75 64 70 [0-32] 3c 44 65 73 74 49 70 3e}  //weight: 1, accuracy: Low
        $x_1_7 = "UDPFLOOD Flood Start On started" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule DDoS_Linux_Flooder_M_2147813596_0
{
    meta:
        author = "defender2yara"
        detection_name = "DDoS:Linux/Flooder.M!xp"
        threat_id = "2147813596"
        type = "DDoS"
        platform = "Linux: Linux platform"
        family = "Flooder"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "floodport" ascii //weight: 2
        $x_1_2 = "CUSTOM-UDP" ascii //weight: 1
        $x_1_3 = "Usage: %s <IP> <PORT> <PAYLOAD>" ascii //weight: 1
        $x_1_4 = "Attack should be started now." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule DDoS_Linux_Flooder_SV_2147814695_0
{
    meta:
        author = "defender2yara"
        detection_name = "DDoS:Linux/Flooder.SV!xp"
        threat_id = "2147814695"
        type = "DDoS"
        platform = "Linux: Linux platform"
        family = "Flooder"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Usage: %s <Host>" ascii //weight: 2
        $x_2_2 = "Setting up sockets..." ascii //weight: 2
        $x_2_3 = "Start flooding..." ascii //weight: 2
        $x_2_4 = "floodport" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule DDoS_Linux_Flooder_E_2147815378_0
{
    meta:
        author = "defender2yara"
        detection_name = "DDoS:Linux/Flooder.E!xp"
        threat_id = "2147815378"
        type = "DDoS"
        platform = "Linux: Linux platform"
        family = "Flooder"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "fnAttackInformation" ascii //weight: 1
        $x_1_2 = "dqyefldi/response.php" ascii //weight: 1
        $x_1_3 = "ChangetoDnsNameFormat" ascii //weight: 1
        $x_1_4 = "DNS Flooder v1.1" ascii //weight: 1
        $x_1_5 = "Usage: %s <target IP/hostname>" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule DDoS_Linux_Flooder_F_2147815379_0
{
    meta:
        author = "defender2yara"
        detection_name = "DDoS:Linux/Flooder.F!xp"
        threat_id = "2147815379"
        type = "DDoS"
        platform = "Linux: Linux platform"
        family = "Flooder"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "flood" ascii //weight: 1
        $x_1_2 = "ldap.c" ascii //weight: 1
        $x_1_3 = "Starting flood..." ascii //weight: 1
        $x_1_4 = "%s IP PORT ldap.txt 2 -1 TIME" ascii //weight: 1
        $x_1_5 = "Usage: %s <target IP> <reflection file>" ascii //weight: 1
        $x_1_6 = "Usage: %s <target IP> <port> <reflection file> " ascii //weight: 1
        $x_1_7 = "Flooded by Keijyy!..." ascii //weight: 1
        $x_1_8 = "Uzycie: %s <ip gry> <port gry> " ascii //weight: 1
        $x_1_9 = "Start Up DDOS..." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule DDoS_Linux_Flooder_G_2147815380_0
{
    meta:
        author = "defender2yara"
        detection_name = "DDoS:Linux/Flooder.G!xp"
        threat_id = "2147815380"
        type = "DDoS"
        platform = "Linux: Linux platform"
        family = "Flooder"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "floodport" ascii //weight: 1
        $x_1_2 = "BrownStarTeam" ascii //weight: 1
        $x_1_3 = "B0STANLI" ascii //weight: 1
        $x_1_4 = "tcpcsum" ascii //weight: 1
        $x_1_5 = "Spoofed UDP Flooder" ascii //weight: 1
        $x_1_6 = "SSYN Flooder by LSDEV" ascii //weight: 1
        $x_1_7 = "zel DDoS Script." ascii //weight: 1
        $x_1_8 = "%s <IP> <Port>" ascii //weight: 1
        $x_1_9 = "%s <target IP> <port to be flooded>" ascii //weight: 1
        $x_1_10 = "m: %s <hedef IP> <target Port>" ascii //weight: 1
        $x_1_11 = "DDOSTHAILAND.XYZ" ascii //weight: 1
        $x_1_12 = "BANKTY DDOS FOR FARKHOST RANDOM.." ascii //weight: 1
        $x_1_13 = "Starting Flood On Xbox Live..." ascii //weight: 1
        $x_1_14 = "Attacking Started.." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule DDoS_Linux_Flooder_I_2147815381_0
{
    meta:
        author = "defender2yara"
        detection_name = "DDoS:Linux/Flooder.I!xp"
        threat_id = "2147815381"
        type = "DDoS"
        platform = "Linux: Linux platform"
        family = "Flooder"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Usage: %s <target IP>" ascii //weight: 1
        $x_1_2 = "ISSYN" ascii //weight: 1
        $x_1_3 = "Flooding: %s" ascii //weight: 1
        $x_1_4 = "Start flooding ..." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule DDoS_Linux_Flooder_B_2147819402_0
{
    meta:
        author = "defender2yara"
        detection_name = "DDoS:Linux/Flooder.B!MTB"
        threat_id = "2147819402"
        type = "DDoS"
        platform = "Linux: Linux platform"
        family = "Flooder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "rand_cmwc" ascii //weight: 1
        $x_1_2 = "setup_udp_header" ascii //weight: 1
        $x_1_3 = "setup_ip_header" ascii //weight: 1
        $x_1_4 = "csum" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule DDoS_Linux_Flooder_B_2147828998_0
{
    meta:
        author = "defender2yara"
        detection_name = "DDoS:Linux/Flooder.B!xp"
        threat_id = "2147828998"
        type = "DDoS"
        platform = "Linux: Linux platform"
        family = "Flooder"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 44 24 3c b8 94 a4 04 08 c7 44 24 08 05 00 00 00 89 44 24 04 8d 44 24 14 89 04 24 e8 e8 e5 ff ff 8d 44 24 14 89 44 24 08 c7 44 24 04 15 89 00 00 8b 44 24 3c 89 04 24 e8 ac e5 ff ff 85 c0 79 18 c7 04 24 bd a4 04 08}  //weight: 1, accuracy: High
        $x_1_2 = {b8 e4 a1 04 08 c7 44 24 0c 00 00 00 00 89 44 24 08 c7 44 24 04 00 00 00 00 8d 44 24 34 89 04 24 e8 d5 e5 ff ff b8 3d a2 04 08 c7 44 24 0c 00 00 00 00 89 44 24 08 c7 44 24 04 00 00 00 00 c7 04 24 7c b9 04 08}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

