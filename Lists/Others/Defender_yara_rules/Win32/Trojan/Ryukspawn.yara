rule Trojan_Win32_Ryukspawn_B_2147909848_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ryukspawn.B"
        threat_id = "2147909848"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ryukspawn"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {77 00 6d 00 69 00 63 00 [0-32] 77 00 69 00 6e 00 33 00 32 00 5f 00 70 00 72 00 6f 00 63 00 65 00 73 00 73 00 [0-240] 72 00 75 00 6e 00 64 00 6c 00 6c 00}  //weight: 4, accuracy: Low
        $x_1_2 = ":\\perflogs\\" wide //weight: 1
        $x_1_3 = ":\\programdata\\" wide //weight: 1
        $x_1_4 = ":\\users\\public\\" wide //weight: 1
        $x_1_5 = "arti64.dll" wide //weight: 1
        $x_1_6 = "calc.dll" wide //weight: 1
        $x_1_7 = "atomicred" wide //weight: 1
        $x_1_8 = {74 00 61 00 62 00 6c 00 65 00 61 00 75 00 5c 00 [0-240] 5c 00 2e 00 2e 00 5c 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Ryukspawn_A_2147909864_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ryukspawn.A"
        threat_id = "2147909864"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ryukspawn"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {77 00 6d 00 69 00 63 00 [0-32] 70 00 72 00 6f 00 63 00 65 00 73 00 73 00 [0-32] 63 00 72 00 65 00 61 00 74 00 65 00 [0-240] 72 00 75 00 6e 00 64 00 6c 00 6c 00}  //weight: 4, accuracy: Low
        $x_1_2 = ":\\perflogs\\" wide //weight: 1
        $x_1_3 = ":\\programdata\\" wide //weight: 1
        $x_1_4 = ":\\users\\public\\" wide //weight: 1
        $x_1_5 = "arti64.dll" wide //weight: 1
        $x_1_6 = "send.css" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Ryukspawn_E_2147914623_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ryukspawn.E"
        threat_id = "2147914623"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ryukspawn"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {70 00 77 00 73 00 68 00 [0-80] 69 00 65 00 78 00 39 00 30 00 02 50 77 00 65 00 62 00 63 00 6c 00 69 00 65 00 6e 00 74 00 [0-80] 68 00 74 00 74 00 70 00}  //weight: 4, accuracy: Low
        $x_4_2 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 [0-80] 69 00 65 00 78 00 39 00 30 00 02 50 77 00 65 00 62 00 63 00 6c 00 69 00 65 00 6e 00 74 00 [0-80] 68 00 74 00 74 00 70 00}  //weight: 4, accuracy: Low
        $x_1_3 = ".sslip.io" wide //weight: 1
        $x_1_4 = "//104.168.237.21" wide //weight: 1
        $x_1_5 = "//45.136.230.191" wide //weight: 1
        $x_1_6 = "//188.42.253.43" wide //weight: 1
        $x_1_7 = {64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 73 00 74 00 72 00 69 00 6e 00 67 00 [0-80] 2f 00 2f 00 31 00 32 00 37 00 2e 00 30 00 2e 00 30 00 2e 00 31 00 3a 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_4_*))) or
            (all of ($x*))
        )
}

