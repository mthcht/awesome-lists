rule Virus_Win32_Nabucur_A_2147690213_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Nabucur.gen!A"
        threat_id = "2147690213"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Nabucur"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {60 0f 31 33 c2 61}  //weight: 1, accuracy: High
        $x_1_2 = {0f c8 93 0f cb 87 de 0f ce 87 f7 0f cf 41 3b ca 75 ee}  //weight: 1, accuracy: High
        $x_1_3 = {33 d2 bb 05 00 00 00 f7 f3 8b 75 08 83 c2 03 8b ca e2 fe}  //weight: 1, accuracy: High
        $x_1_4 = {31 06 83 c6 04 83 c1 04 81 f9 ?? ?? 00 00 7c f0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Virus_Win32_Nabucur_B_2147691446_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Nabucur.gen!B"
        threat_id = "2147691446"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Nabucur"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {74 61 73 6b 6b 69 6c 6c 20 2f 46 49 20 22 55 53 45 52 4e 41 4d 45 20 65 71 20 4a 6f 68 6e 44 6f 65 22 20 2f 46 20 2f 49 4d 20 [0-11] 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_2 = "There are two ways to pay a fine:" wide //weight: 1
        $x_1_3 = {0f c8 93 0f cb 87 de 0f ce 87 f7 0f cf 41 3b ca 75 ee}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

