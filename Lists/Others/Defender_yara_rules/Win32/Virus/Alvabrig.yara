rule Virus_Win32_Alvabrig_D_2147623476_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Alvabrig.gen!D"
        threat_id = "2147623476"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Alvabrig"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5e 8b 5e 24 03 dd 66 8b 0c 4b 8b 5e 1c 03 dd 8b 04 8b 03 c5 5e c3}  //weight: 1, accuracy: High
        $x_1_2 = {56 8b 75 3c 8b 74 2e 78 03 f5 56 8b 76 20}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Virus_Win32_Alvabrig_A_2147623559_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Alvabrig.gen!A"
        threat_id = "2147623559"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Alvabrig"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {78 0c 8b 40 0c 8b 70 1c ad 8b 40 08 eb 09 8b 40 34 8d 40 7c 8b 40 3c 95 e8 00 00 00 00 5e 90}  //weight: 1, accuracy: High
        $x_1_2 = {81 7f 08 70 00 65 00}  //weight: 1, accuracy: High
        $x_1_3 = {81 7f f9 00 73 00 66}  //weight: 1, accuracy: High
        $x_1_4 = "%s\\dtw5d\\FromActiveX%08X%08X_%08d_%s" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Virus_Win32_Alvabrig_C_2147623560_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Alvabrig.gen!C"
        threat_id = "2147623560"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Alvabrig"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {78 0c 8b 40 0c 8b 70 1c ad 8b 40 08 eb 09 8b 40 34 8d 40 7c 8b 40 3c 95 e8 00 00 00 00 5e 90}  //weight: 1, accuracy: High
        $x_1_2 = {ff 16 89 45 fc 53 50 ff 56 04 89 45 f4}  //weight: 1, accuracy: High
        $x_1_3 = {39 18 39 18 74 11 81 38 79 74 60 83 74 09 c1 08 02 81 30 79 74 60 83 83 c0 04 e2 e4}  //weight: 1, accuracy: High
        $x_1_4 = {5c 6c 64 73 68 79 72 2e 6f 6c 64 00 77 69 6e 69 6e 65 74 2e 64 6c 6c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Virus_Win32_Alvabrig_B_2147623561_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Alvabrig.gen!B"
        threat_id = "2147623561"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Alvabrig"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {78 0c 8b 40 0c 8b 70 1c ad 8b 40 08 eb 09 8b 40 34 8d 40 7c 8b 40 3c 95 e8 00 00 00 00 5e 90}  //weight: 1, accuracy: High
        $x_1_2 = {ff 75 08 ff 96 88 00 00 00 81 7d f0 54 45 64 69 75 0d}  //weight: 1, accuracy: High
        $x_1_3 = {6c 64 75 70 64 74 2e 6a 70 67 00 4f 70 65 72 61 2f 39 2e 32 30}  //weight: 1, accuracy: High
        $x_1_4 = {64 74 77 35 64 00 64 74 77 35 64 5c 25 73 5f 25 30 38 64 2e 6c 70 73 74 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

