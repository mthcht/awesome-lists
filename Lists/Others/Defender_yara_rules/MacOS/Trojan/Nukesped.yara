rule Trojan_MacOS_Nukesped_G_2147830629_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Nukesped.G!MTB"
        threat_id = "2147830629"
        type = "Trojan"
        platform = "MacOS: "
        family = "Nukesped"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {58 be 13 9e 14 6c 77 6b ad 15 1e 30 34 c0 4c e8 7a 87 1a f8 5e 6e be ac f4 ff 34 9e b7 3b d9 90 a3 51 46 c1 4b de 5e f1 d1 33 3e 5a 28 d9 2d d6 a4 d5 be 92 0f ab f4 bd a5 c8 3b 8b a1 ca e5 29 e1 02 19 39 57 1e 12 69 32 fd a1 7d f5 cb 9e 9c 4a f4 40 92 f3 54 97 bb 9b ff d1 e9 c6 ba 8f a9 9e bd 26 6d 6d 82 94 8c 20 df 9b f1 af dd c7 5f 1a 33 39 86 23 cc 1f a8 ee f0 d9 d5}  //weight: 1, accuracy: High
        $x_1_2 = {35 70 22 6b 8d 06 a5 6c 4b bd 96 06 0a 93 35 0f e4 42 ca c0 60 43 8d 59 35 e8 91 6e 19 18 df 99 5a 4b 19 ca 65 4e 99 91 c7 5d e0 81 73 98 89 e8 47 0c a4 7e ea 5f 19 29 97 46 d3 d1 78 2c 92 5c a3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_MacOS_Nukesped_H_2147850534_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Nukesped.H!MTB"
        threat_id = "2147850534"
        type = "Trojan"
        platform = "MacOS: "
        family = "Nukesped"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {39 13 c0 b5 94 5e d1 44 10 0c 99 68 4c b4 47 0b a0 d0 d6 75 d8 f3 dc b6 5c a6 8a b3 2b d9 ff 8d 28 19 21 cc}  //weight: 1, accuracy: High
        $x_1_2 = {35 35 35 35 34 39 34 34 65 34 35 34 36 30 31 33 64 62 30 66 33 35 38 35 62 63 37 30 36 62 65 32 34 35 35 64 30 38 34 65 00 fe 91 3b 84 0b 01 ce 04 da a4 bd 1f e8 61 14 b4 4e 79 d1 92 0c ac d2 4b b0 0e 38 ad 3f 88 54 ec}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_MacOS_Nukesped_I_2147919059_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Nukesped.I!MTB"
        threat_id = "2147919059"
        type = "Trojan"
        platform = "MacOS: "
        family = "Nukesped"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 89 e0 31 c9 ?? ?? ?? ?? ?? ?? ?? 89 ce 83 e6 1f 8a 14 3e 30 14 0b 48 ff c1 48 39 c8}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 4d ec 89 ce c1 ee 02 83 e6 3f 42 8a 34 06 89 c7 40 88 34 3a c1 e1 04 83 e1 30 44 89 ce c1 ee 04 83 e6 0f 48 09 ce 41 8a 0c 30}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Nukesped_J_2147920164_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Nukesped.J!MTB"
        threat_id = "2147920164"
        type = "Trojan"
        platform = "MacOS: "
        family = "Nukesped"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/tmp/GoogleMsgStatus.pdf" ascii //weight: 1
        $x_1_2 = "/tmp/NetMsgStatus" ascii //weight: 1
        $x_1_3 = "netboturl" ascii //weight: 1
        $x_1_4 = "googleboturl" ascii //weight: 1
        $x_1_5 = "buy2x.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Nukesped_K_2147923437_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Nukesped.K!MTB"
        threat_id = "2147923437"
        type = "Trojan"
        platform = "MacOS: "
        family = "Nukesped"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 48 89 e5 48 83 ec 10 48 89 7d f8 48 8b 7f 08 e8 ?? ?? ?? ?? 48 8b 7d f8 48 8b 7f 10 ff ?? ?? ?? ?? ?? 48 8b 45 f8 48 83 c4 10 5d c3}  //weight: 1, accuracy: Low
        $x_1_2 = {48 89 45 f8 75 ?? 48 8b 3d d0 69 00 00 e8 ?? ?? ?? ?? 48 89 c7 e8 ?? ?? ?? ?? 48 89 c1 48 89 c8 48 89 0d f6 6c 00 00 48 89 45 f8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

