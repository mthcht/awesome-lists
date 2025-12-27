rule Trojan_Linux_Flooder_B_2147762250_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Flooder.B!MTB"
        threat_id = "2147762250"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Flooder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SYN flooder thread" ascii //weight: 1
        $x_1_2 = "Run a d.o.s. attack against an IP address" ascii //weight: 1
        $x_1_3 = "plugin_load" ascii //weight: 1
        $x_1_4 = "plug-ins/dos_attack/dos_attack.c" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Linux_Flooder_C_2147766299_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Flooder.C!MTB"
        threat_id = "2147766299"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Flooder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Starting Flood" ascii //weight: 1
        $x_1_2 = "backdoor.c" ascii //weight: 1
        $x_1_3 = {77 67 65 74 20 2d 71 48 89 85 70 fe ff ff 48 b8 20 2d 2d 64 65 6c 65 74 48 89 85 78 fe ff ff 48 b8 65 2d 61 66 74 65 72 20 48 89 85 80 fe ff ff 48 b8 68 74 74 70 73 3a 2f 2f 48 89 85 88 fe ff ff 48 b8 67 72 61 62 69 66 79 2e 48 89 85 90 fe ff ff 48 b8 6c 69 6e 6b 2f 4b 53 4e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Linux_Flooder_D_2147766301_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Flooder.D!MTB"
        threat_id = "2147766301"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Flooder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "telnetattack" ascii //weight: 1
        $x_1_2 = "sentinelscanner" ascii //weight: 1
        $x_1_3 = "ddos" ascii //weight: 1
        $x_1_4 = "chargenscanner" ascii //weight: 1
        $x_1_5 = "cerberus" ascii //weight: 1
        $x_1_6 = "joomlascan" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_Linux_Flooder_D_2147816099_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Flooder.D!xp"
        threat_id = "2147816099"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Flooder"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "WQRGQREQRTQRFQRLQROQROQRD" ascii //weight: 1
        $x_1_2 = "bQRuQRsQRyQRbQRoQRtQRnQReQRt" ascii //weight: 1
        $x_1_3 = "KQRIQRLQRLQRAQRLQRL" ascii //weight: 1
        $x_1_4 = "bQRuQRsQRyQRbQRoQRxQRtQReQRrQRrQRoQRrQRiQRsQRt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Linux_Flooder_A_2147816820_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Flooder.A!xp"
        threat_id = "2147816820"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Flooder"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Usage: %s [-T -U -I -N -s -h -d -p -q -l -t]" ascii //weight: 2
        $x_2_2 = "inject_iphdr" ascii //weight: 2
        $x_2_3 = "T:UINs:h:d:p:q:l:t:" ascii //weight: 2
        $x_1_4 = "Geminid" ascii //weight: 1
        $x_1_5 = "TCP Attack" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Linux_Flooder_E_2147833475_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Flooder.E!MTB"
        threat_id = "2147833475"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Flooder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sybex.c" ascii //weight: 1
        $x_1_2 = "floodport" ascii //weight: 1
        $x_1_3 = "randommexico" ascii //weight: 1
        $x_1_4 = "Priv8 TCP Bypass" ascii //weight: 1
        $x_1_5 = "Sending attack" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Linux_Flooder_F_2147834959_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Flooder.F!MTB"
        threat_id = "2147834959"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Flooder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Preparing payload" ascii //weight: 1
        $x_2_2 = {b8 e8 03 00 00 99 f7 7d ?? 69 c0 e8 03 00 00 89 c7 e8 ?? ?? ?? ?? 8b 15 ?? ?? 20 00 8b 45 ?? 0f af d0 8b 45 ?? 39 c2 76 2c 8b 05 ?? ?? 20 00 85 c0 7f 11 8b 05 ?? ?? 20 00 83 c0 64 89 05 ?? ?? 20 00 eb 46 8b 05 ?? ?? 20 00 83 e8 01 89 05 ?? ?? 20 00 eb 35 8b 05 ?? ?? 20 00 83 c0 01 89 05 ?? ?? 20 00 8b 05 ?? ?? 20 00 83 f8 19 76 11 8b 05 ?? ?? 20 00 83 e8 19 89 05 ?? ?? 20 00 eb 0a}  //weight: 2, accuracy: Low
        $x_1_3 = {48 83 ec 28 48 89 7d d8 48 89 75 d0 89 55 cc 83 7d cc ?? 75 11 48 8b 45 d8 48 89 c7 e8 ?? ?? ff ff e9 ?? ?? ?? ?? e8 ?? fb ff ff 89 c1 ba 09 04 02 81 89 c8 f7 ea 8d 04 0a c1 f8 07 89 c2 89 c8 c1 f8 1f 89 d3 29 c3 [0-21] 89 cb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Linux_Flooder_G_2147922858_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Flooder.G!MTB"
        threat_id = "2147922858"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Flooder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 63 61 6e 27 74 20 72 65 73 6f 6c 76 65 20 64 65 73 74 69 6e 61 74 69 6f 6e 20 68 6f 73 74 6e 61 6d 65 0a 00 73 6f 63 6b 65 74 00}  //weight: 1, accuracy: High
        $x_1_2 = {63 61 6e 27 74 20 72 65 73 6f 6c 76 65 20 73 6f 75 72 63 65 20 68 6f 73 74 6e 61 6d 65 0a 00 00 63 61 6e 27 74 20 72 65 73 6f 6c 76 65 20 64 65 73 74 69 6e 61 74 69 6f 6e 20 68 6f 73 74 6e 61 6d 65 0a 00 73 6f 63 6b 65 74 00 0a 57 65 20 68 61 76 65 20 49 50 5f 48 44 52 49 4e 43 4c 20 0a 00 73 65 74 73 6f 63 6b 6f 70 74 20 49 50 5f 48 44 52 49 4e 43 4c 00 0a 4e 75 6d 62 65 72 20 6f 66 20 50 61 63 6b 65 74 73 20 73 65 6e 74 3a 0a 00 73 65 6e 64 74 6f 00 0d 53 65 6e 74 20 25 64 20 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Linux_Flooder_H_2147935544_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Flooder.H!MTB"
        threat_id = "2147935544"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Flooder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sendUDPFlood" ascii //weight: 1
        $x_1_2 = "handleIPIPAttack" ascii //weight: 1
        $x_1_3 = "main.SendRawTCP" ascii //weight: 1
        $x_1_4 = "main.sendMinecraftPackets" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Linux_Flooder_I_2147940232_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Flooder.I!MTB"
        threat_id = "2147940232"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Flooder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "main.performHTTPFlood" ascii //weight: 1
        $x_1_2 = "TCPfloodAttack" ascii //weight: 1
        $x_1_3 = "performGREFlood" ascii //weight: 1
        $x_1_4 = "main.udpsmart" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Linux_Flooder_J_2147950396_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Flooder.J!MTB"
        threat_id = "2147950396"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Flooder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {fd 7b be a9 fd 03 00 91 f3 0b 00 f9 f3 00 00 f0 60 82 40 39 20 01 00 37 e0 00 00 d0 00 f4 47 f9 80 00 00 b4 00 00 00 b0 00 e0 26 91 5f fe ff 97 20 00 80 52 60 82 00 39 f3 0b 40 f9 fd 7b c2 a8}  //weight: 1, accuracy: High
        $x_1_2 = {80 ca 63 38 61 7c 40 93 80 01 00 35 81 02 01 8b 38 04 00 39 37 0c 00 39 e1 43 01 91 40 fc ff 97 e0 2f 40 f9 01 fc 50 93 00 00 01 0b 00 04 c0 5a 80 02 00 79 c9 ff ff 17}  //weight: 1, accuracy: High
        $x_1_3 = {ff 03 05 d1 21 1c 00 12 3f 08 00 71 e2 00 00 f0 e1 03 00 aa e4 03 00 91 fd 7b 12 a9 fd 83 04 91 05 23 80 d2 00 00 80 52 f3 9b 00 f9 33 00 80 52 43 08 40 f9 e3 8f 00 f9 03 00 80 d2 e2 03 13 2a 83 03 80 52 63 12 83 1a 8c ff ff 97 c0 01 00 b5 e0 00 00 d0 01 2c 46 f9 00 00 00 b0 00 e0 0d 91 a6 fc ff 97 e0 03 13 2a}  //weight: 1, accuracy: High
        $x_1_4 = {7f 02 00 f1 76 46 00 91 d6 06 96 9a 7f f6 03 f1 c2 92 5a fa 48 fe ff 54 3f 3f 00 71 08 fe ff 54 e2 03 16 aa e0 03 14 aa 39 13 1d 53 01 00 80 52 ad fc ff 97 39 03 00 32 20 00 80 52 99 0a 00 39 80 16 00 39 80 36 00 91 1f 00 15 eb e2 00 00 54 01 00 13 8b bf 02 01 eb 02 01 00 54 00 7d 20 d4 f3 03 00 aa e7 ff ff 17}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

