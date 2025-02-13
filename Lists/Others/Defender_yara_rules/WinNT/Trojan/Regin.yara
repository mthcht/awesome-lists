rule Trojan_WinNT_Regin_A_2147644054_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Regin.gen.A!dha"
        threat_id = "2147644054"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Regin"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ff 75 10 8b 46 64 c1 e8 02 50 ff 75 0c e8}  //weight: 1, accuracy: High
        $x_1_2 = {05 00 00 84 c0 75 0e ff 75 10 8b 45 0c 53 ff 30 e8}  //weight: 1, accuracy: High
        $x_1_3 = {8b 45 fc 8b 40 28 03 45 08 53 ff 75 08 ff d0 8b d8 f7 db 1a db fe c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_WinNT_Regin_B_2147644208_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Regin.gen.B!dha"
        threat_id = "2147644208"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Regin"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3b f0 72 dc 6a 03 57 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 83 c4 0c 85 c0 75 04 c6 45 ff 01}  //weight: 1, accuracy: Low
        $x_1_2 = {c7 07 fe ba dc fe 89 47 04}  //weight: 1, accuracy: High
        $x_1_3 = {c7 04 24 11 77 11 77 be 11 66 11 66 ff e0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_WinNT_Regin_C_2147683214_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Regin.gen.C!dha"
        threat_id = "2147683214"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Regin"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 46 0c 8b 40 64 c1 e8 02 50 ff 75 0c e8}  //weight: 1, accuracy: High
        $x_1_2 = {6a 41 eb 02 6a 46 5e ff 75 f8 e8}  //weight: 1, accuracy: High
        $x_1_3 = {8b 40 28 6a 00 03 [0-3] [0-3] ff d0 f7 d8 1a c0 [0-2] fe c0 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_WinNT_Regin_C_2147690231_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Regin.C!dha"
        threat_id = "2147690231"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Regin"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c7 04 24 11 77 11 77 be 11 66 11 66 ff e0}  //weight: 1, accuracy: High
        $x_1_2 = {8b 45 fc 8b 40 28 03 45 08 53 ff 75 08 ff d0 8b d8 f7 db 1a db}  //weight: 1, accuracy: High
        $x_1_3 = {c6 45 d8 4d c6 45 d9 6d c6 45 da 48 c6 45 db 69 c6 45 dc 67 c6 45 dd 68 c6 45 de 65 c6 45 df 73 c6 45 e0 74 c6 45 e1 55 c6 45 e2 73 c6 45 e3 65 c6 45 e4 72 c6 45 e5 41 c6 45 e6 64 c6 45 e7 64 c6 45 e8 72 c6 45 e9 65 c6 45 ea 73 c6 45 eb 73}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_WinNT_Regin_D_2147690332_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Regin.D!dha"
        threat_id = "2147690332"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Regin"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {c7 04 24 11 77 11 77 be 11 66 11 66 ff e0}  //weight: 2, accuracy: High
        $x_2_2 = {00 73 68 69 74 00 00 00 00 44 57 58 00 53 53 4d 00}  //weight: 2, accuracy: High
        $x_1_3 = {57 57 6a 64 68 ?? ?? ?? ?? 6a 6e}  //weight: 1, accuracy: Low
        $x_2_4 = {77 69 6e 73 74 61 30 00 70 86 75 31 e7 e1 e1 21 c6 ba e7 a8 3c 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

