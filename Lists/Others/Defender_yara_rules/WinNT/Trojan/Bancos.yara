rule Trojan_WinNT_Bancos_G_2147647309_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Bancos.G"
        threat_id = "2147647309"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Bancos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 46 50 8b 46 60 c6 46 20 00 c7 46 08 04 04 00 00 83 e8 24 c6 00 06 89 78 14 8b 4d fc 89 48 18 89 58 04 c7 40 08 0d 00 00 00 8b 4d fc 89 48 0c 8b 46 60}  //weight: 1, accuracy: High
        $x_1_2 = "\\ARQUIV~1\\GbPlugin\\gb" wide //weight: 1
        $x_1_3 = "\\WINDOWS\\system32\\drivers\\gbpkm.sys" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_WinNT_Bancos_H_2147648210_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Bancos.H"
        threat_id = "2147648210"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Bancos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "bancobrasil.com.br" ascii //weight: 1
        $x_1_2 = "GbPlugin" wide //weight: 1
        $x_1_3 = "HarddiskVolume1\\Windows\\system32\\drivers\\etc\\hosts" wide //weight: 1
        $x_1_4 = {0f b6 c0 85 c0 74 0a b8 84 01 00 c0 e9 ?? ?? 00 00 6a 00 6a 00 6a 20 6a 05}  //weight: 1, accuracy: Low
        $x_1_5 = {01 00 89 45 f4 c7 05 ?? ?? 01 00 18 00 00 00 c7 05 ?? ?? 01 00 00 00 00 00 c7 05 ?? ?? 01 00 40 00 00 00 c7 05 ?? ?? 01 00 ?? ?? 01 00 c7 05 ?? ?? 01 00 00 00 00 00 c7 05 ?? ?? 01 00 00 00 00 00 68 ?? ?? ?? 00 ff 15 ?? ?? 01 00 89 45 f4 68 ?? ?? 01 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_WinNT_Bancos_K_2147678813_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Bancos.K"
        threat_id = "2147678813"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Bancos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5a 77 55 6e 6c 6f 61 64 44 72 69 76 65 72 00}  //weight: 1, accuracy: High
        $x_1_2 = {5c 00 3f 00 3f 00 5c 00 43 00 3a 00 5c 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 65 00 64 00 20 00 70 00 72 00 6f 00 67 00 72 00 61 00 6d 00 20 00 66 00 69 00 6c 00 65 00 73 00 5c 00 67 00 62 00 69 00 65 00 68 00 2e 00 67 00 6d 00 64 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {5c 00 3f 00 3f 00 5c 00 43 00 3a 00 5c 00 57 00 49 00 4e 00 44 00 4f 00 57 00 53 00 5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 64 00 72 00 69 00 76 00 65 00 72 00 73 00 5c 00 65 00 74 00 63 00 5c 00 68 00 6f 00 73 00 74 00 73 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {5c 00 3f 00 3f 00 5c 00 43 00 3a 00 5c 00 61 00 72 00 71 00 75 00 69 00 76 00 6f 00 73 00 20 00 64 00 65 00 20 00 70 00 72 00 6f 00 67 00 72 00 61 00 6d 00 61 00 73 00 5c 00 67 00 62 00 70 00 6c 00 75 00 67 00 69 00 6e 00 5c 00 67 00 62 00 70 00 64 00 69 00 73 00 74 00 2e 00 64 00 6c 00 6c 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {5c 00 3f 00 3f 00 5c 00 43 00 3a 00 5c 00 61 00 72 00 71 00 75 00 69 00 76 00 6f 00 73 00 20 00 64 00 65 00 20 00 70 00 72 00 6f 00 67 00 72 00 61 00 6d 00 61 00 73 00 5c 00 67 00 62 00 70 00 6c 00 75 00 67 00 69 00 6e 00 5c 00 47 00 62 00 70 00 53 00 76 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

