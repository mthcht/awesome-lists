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

