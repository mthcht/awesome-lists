rule Trojan_WinNT_Duqu_A_2147650508_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Duqu.A"
        threat_id = "2147650508"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Duqu"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c0 0d 8d 4e 0d 8b d0 2b d1 8b 09 2b 08 3b ca 0f 94 c0}  //weight: 1, accuracy: High
        $x_1_2 = {8b 44 24 04 81 60 1c 7f ff ff ff 6a 00 c7 46 20 01 00 00 00 ff 15 ?? ?? ?? ?? 6a 01 68 24 10 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {8b d1 0f af d1 b8 ?? ?? ?? ?? f7 e2 8b c1 69 c0 ?? ?? ?? ?? c1 ea 0c 8d 54 02 01 83 c6 01 33 ca}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_WinNT_Duqu_B_2147650655_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Duqu.B"
        threat_id = "2147650655"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Duqu"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 fd 06 13 a8 50 e8 ?? ?? ?? ?? 8d 4c 24 ?? 68 55 87 fe 7a 51}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_WinNT_Duqu_C_2147651067_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Duqu.C"
        threat_id = "2147651067"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Duqu"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c0 66 3b c1 73 ?? 0f b7 c7 6b c0 28 03 c6 8b 48 08 8b 50 10 3b ca 72 02 8b ca 8b 40 0c 3b d8 72}  //weight: 1, accuracy: Low
        $x_1_2 = {38 5d 0c 74 ?? 68 ?? ?? ?? ?? ff 75 08 e8 ?? ?? ?? ?? 3b c3 75 07 b8 01 00 00 c0 eb 2b 53 50 8d 45 ?? 50 e8 ?? ?? ?? ?? 83 c4 0c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_WinNT_Duqu_D_2147655198_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Duqu.D"
        threat_id = "2147655198"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Duqu"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c0 66 3b c1 73 ?? 0f b7 c7 6b c0 28 03 c6 8b 48 08 8b 50 10 3b ca 72 02 8b ca 8b 40 0c 3b d8 72}  //weight: 1, accuracy: Low
        $x_1_2 = {66 c7 03 4d 5a 8b 0d ?? ?? ?? ?? c7 04 19 50 45 00 00 8b 15 ?? ?? ?? ?? 83 c4 0c 66 c7 04 1a 0b 01 a1 ?? ?? ?? ?? 68 98 00 00 00 03 c3 6a 00 50 89 45 04 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

