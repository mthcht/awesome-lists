rule Trojan_Win32_Valden_A_2147663920_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Valden.A"
        threat_id = "2147663920"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Valden"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {73 65 6e 64 66 69 6c 65 73 00 00 00 73 65 6c 66 64 65 73 74 72 75 63 74 00 00 00 00 2f 43 20 52 44 20 2f 53 20 2f 51 20 25 25 54 45 4d 50 25 25}  //weight: 1, accuracy: High
        $x_1_2 = {b9 0b 00 00 00 f7 f9 8b fa 83 ff 01 7f 05 bf ?? 00 00 00 33 f6 85 ff 7e 1d e8 ?? ?? ?? ?? 33 d2 b9 34 00 00 00 f7 f1 46 3b f7 8a 92 ?? ?? ?? ?? 88 54 1e ff 7c e3}  //weight: 1, accuracy: Low
        $x_1_3 = {70 69 6e 70 61 64 00 00 00 77 69 6e 00 63 63 61 72 64 3d 31 00 63 63 61 72 64 3d 30}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Valden_C_2147680276_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Valden.C"
        threat_id = "2147680276"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Valden"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "EXPORT HKCU\\Software\\GbPlugin" ascii //weight: 1
        $x_1_2 = "EXPORT HKCU\\Software\\GbAs" ascii //weight: 1
        $x_1_3 = "C:\\Arquivos de Programas\\GbPlugin\\bb.gpc" ascii //weight: 1
        $x_1_4 = "C:\\Program Files\\GbPlugin\\bb.gpc" ascii //weight: 1
        $x_1_5 = {53 79 6e 63 4d 6f 64 65 35 00}  //weight: 1, accuracy: High
        $x_1_6 = {73 65 6c 66 64 65 73 74 72 75 63 74 00}  //weight: 1, accuracy: High
        $x_1_7 = "data=hello&user" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule Trojan_Win32_Valden_D_2147680277_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Valden.D"
        threat_id = "2147680277"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Valden"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/p/server" ascii //weight: 1
        $x_1_2 = "data=info&bank=2&user" ascii //weight: 1
        $x_1_3 = "formSicrediInternet\" method=\"POST\"" ascii //weight: 1
        $x_1_4 = "santandernetibe.com.br/topos/IBPJ_Topo.asp" ascii //weight: 1
        $x_1_5 = "bancobrasil.com.br/aapf/" ascii //weight: 1
        $x_1_6 = "hsbc.uniaodebancos.net" ascii //weight: 1
        $x_1_7 = "sicredi.com.br/websitesicredi/" ascii //weight: 1
        $x_3_8 = {c1 e0 08 0b c1 0f b6 8d 9e ff 00 00 c1 e0 08 0b c1 0f b6 8d 9f ff 00 00 c1 e0 08 6a 04 89 5d 94 0b c1 5f eb 64}  //weight: 3, accuracy: High
        $x_3_9 = {81 6d fc 47 86 c8 61 03 f1 33 f7 03 c6 8b f0 c1 ee 05 8b f8 c1 e7 04 33 f7 8b 7d fc c1 ef 0b 83 e7 03}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((7 of ($x_1_*))) or
            ((1 of ($x_3_*) and 4 of ($x_1_*))) or
            ((2 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Valden_E_2147681110_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Valden.E"
        threat_id = "2147681110"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Valden"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 64 61 74 61 3d 69 6e 66 6f 26 62 61 6e 6b 3d ?? 26 75 73 65 72 5f 6e 61 6d 65 3d 25 73}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 77 3c 8d 45 ?? 50 6a 40 03 f7 ff 76 50 57 ff 15 ?? ?? ?? ?? 8b 46 50 03 c7 eb 0a 8b 0f 3b 4d 0c 74 09 83 c7 04 3b f8 72 f2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

