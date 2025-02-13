rule Trojan_Win32_Diamin_F_2147603539_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Diamin.F"
        threat_id = "2147603539"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Diamin"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {6a 00 6a 00 8d 45 f0 50 b9 ?? ?? ?? ?? ba ?? ?? ?? ?? b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 45 f0 e8 ?? ?? ?? ?? 50 6a 00}  //weight: 10, accuracy: Low
        $x_2_2 = {6c 65 72 4d [0-16] 44 69 61}  //weight: 2, accuracy: Low
        $x_2_3 = {44 69 73 69 6e 73 74 61 6c 6c 61 2e 6c 6e 6b [0-16] 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e}  //weight: 2, accuracy: Low
        $x_1_4 = "WCI International rates apply. Maximum time: 20 minutes. CLICK ON YES TO PROCEED!" ascii //weight: 1
        $x_11_5 = {6f 72 65 00 [0-16] 65 78 70 6c [0-32] 6f 76 65 72 2e 20 57 6f 75 6c 64 20 79 6f 75 20 6c 69 6b 65 20 74 6f 20 63 6f 6e 6e 65 63 74 20 61 67 61 69 6e}  //weight: 11, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_2_*))) or
            ((1 of ($x_11_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_11_*) and 2 of ($x_2_*))) or
            ((1 of ($x_11_*) and 1 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Diamin_G_2147604943_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Diamin.G"
        threat_id = "2147604943"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Diamin"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {6a 00 6a 00 8d 45 f0 50 b9 ?? ?? ?? ?? ba ?? ?? ?? ?? b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 45 f0 e8 ?? ?? ?? ?? 50 6a 00}  //weight: 10, accuracy: Low
        $x_10_2 = {68 24 10 00 00 6a 00 6a 00 [0-4] 8d 45 ?? 50 33 c9 ba ?? ?? ?? ?? b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 45 ?? e8 ?? ?? ?? ?? 50 6a 00 6a 00}  //weight: 10, accuracy: Low
        $x_2_3 = {6c 65 72 4d [0-16] 44 69 61 [0-16] 54 52 41 43 4b}  //weight: 2, accuracy: Low
        $x_2_4 = {6c 65 72 4d [0-16] 44 69 61 [0-16] 49 53 49 4f 4e}  //weight: 2, accuracy: Low
        $x_1_5 = "Disinstalla.lnk" ascii //weight: 1
        $x_1_6 = "p://flat.traff" ascii //weight: 1
        $x_1_7 = "ial1.e" ascii //weight: 1
        $x_1_8 = "ti, scegliere \"No\" per accedere direttamente." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 2 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

