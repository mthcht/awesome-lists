rule Trojan_Win32_Ramdo_A_2147684705_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ramdo.A"
        threat_id = "2147684705"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ramdo"
        severity = "Mid"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {64 a1 30 00 00 00 89 45 ?? 8b 45 ?? 8b (40|48) 0c 89 (45|4d) ?? 8b (45|55) ?? 83 (c0|c2) 0c}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 03 6a 00 e8 ?? ?? ?? ?? 83 c4 0c 89 45 fc 8b 45 10 50 8b 4d 0c 51 8b 55 08 52 ff 55 fc}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ramdo_E_2147688104_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ramdo.E"
        threat_id = "2147688104"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ramdo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 03 6a 00 e8 ?? ?? ?? ?? 89 45 fc ff 75 10 ff 75 0c ff 75 08 ff 55 fc}  //weight: 1, accuracy: Low
        $x_1_2 = {68 3e dd ef 6c 6a 03 6a 00 e8}  //weight: 1, accuracy: High
        $x_1_3 = {68 27 a8 02 84 6a 03 6a 00 e8}  //weight: 1, accuracy: High
        $x_1_4 = {89 85 78 ff ff ff 83 bd 78 ff ff ff 00 0f 84 b8 02 00 00 8d 45 84 50 68 00 10 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {89 85 bc fb ff ff 83 bd bc fb ff ff 00 76 0f c7 85 dc fd ff ff 01 00 00 00 e9 ?? ?? 00 00 eb ?? c7 85 b8 fb ff ff 08 02 00 00 83 bd d8 fd ff ff 00 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_Ramdo_F_2147691714_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ramdo.F"
        threat_id = "2147691714"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ramdo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {7d 28 0f b7 4d f8 8b 55 fc 8b 42 04 0f be 0c 08 8b 55 fc 0f b6 02 33 c8 0f b7 55 f8 33 ca 0f b7 45 f8 8b 55 0c 88 0c 02 eb bd}  //weight: 1, accuracy: High
        $x_2_2 = {81 7d f4 39 e8 ab f5 74 09 81 7d f4 27 34 f0 c5 75 12}  //weight: 2, accuracy: High
        $x_1_3 = {68 3e dd ef 6c 6a 03 6a 00 e8}  //weight: 1, accuracy: High
        $x_1_4 = {68 27 a8 02 84 6a 03 6a 00 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Ramdo_G_2147691787_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ramdo.G"
        threat_id = "2147691787"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ramdo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {7d 28 0f b7 ?? f8 8b ?? fc 8b ?? 04 0f be ?? ?? 8b ?? fc 0f b6 ?? 33 ?? 0f b7 ?? f8 33 ?? 0f b7 ?? f8 8b 55 0c 88 ?? ?? eb bd}  //weight: 1, accuracy: Low
        $x_2_2 = {81 7d f4 39 e8 ab f5 74 09 81 7d f4 27 34 f0 c5 75}  //weight: 2, accuracy: High
        $x_1_3 = {68 0a 5a 62 59 6a 01 6a 00 e8}  //weight: 1, accuracy: High
        $x_1_4 = {68 3e dd ef 6c 6a 03 6a 00 e8}  //weight: 1, accuracy: High
        $x_1_5 = {68 27 a8 02 84 6a 03 6a 00 e8}  //weight: 1, accuracy: High
        $x_1_6 = {64 a1 30 00 00 00 89 45 ?? 8b 45 ?? 8b (40|48) 0c 89 (45|4d) ?? 8b (45|55) ?? 83 (c0|c2) 0c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Ramdo_H_2147692029_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ramdo.H"
        threat_id = "2147692029"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ramdo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {81 fe 70 17 00 00 7c ac 83 ff 65 76 18 8b c7 89 45 ec}  //weight: 1, accuracy: High
        $x_1_2 = {2b 45 f0 33 d2 b9 10 27 00 00 f7 f1 3d 60 ea 00 00 0f}  //weight: 1, accuracy: High
        $x_1_3 = {2b 4d f0 b8 59 17 b7 d1 f7 e1 c1 ea 0d 81 fa 60 ea 00 00 0f}  //weight: 1, accuracy: High
        $x_1_4 = {68 3e dd ef 6c 6a 03 6a 00 e8}  //weight: 1, accuracy: High
        $x_1_5 = {68 df c3 86 5d 6a 01 6a 00 e8}  //weight: 1, accuracy: High
        $x_1_6 = {68 7b 17 76 c0 6a 03 6a 00 e8}  //weight: 1, accuracy: High
        $x_1_7 = {68 4f b7 1c 9c 6a 03 6a 00 e8}  //weight: 1, accuracy: High
        $x_1_8 = {68 89 48 f7 23 6a 03 6a 00 e8}  //weight: 1, accuracy: High
        $x_1_9 = {68 11 86 93 3f 6a 03 6a 00 e8}  //weight: 1, accuracy: High
        $x_1_10 = {68 87 31 b8 51 6a 03 6a 00 e8}  //weight: 1, accuracy: High
        $x_1_11 = {68 bc 88 2a 42 6a 03 6a 00 e8}  //weight: 1, accuracy: High
        $x_1_12 = {68 45 7d 80 db 6a 03 56 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

