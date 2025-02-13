rule Virus_WinNT_Cutwail_A_2147632142_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:WinNT/Cutwail.gen!A"
        threat_id = "2147632142"
        type = "Virus"
        platform = "WinNT: WinNT"
        family = "Cutwail"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b9 76 01 00 00 0f 32 66 25 00 f0 81 78 4e 54 68 69 73 74 03 48 eb f0}  //weight: 1, accuracy: High
        $x_1_2 = {55 8b ec 51 e8 ?? ?? ?? ?? 89 45 fc 68 da 84 ae 28 68 28 5f c3 d0 8b 45 fc 50 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Virus_WinNT_Cutwail_B_2147642396_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:WinNT/Cutwail.gen!B"
        threat_id = "2147642396"
        type = "Virus"
        platform = "WinNT: WinNT"
        family = "Cutwail"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 da 84 ae 28 68 28 5f c3 d0 8b 45 fc 50 e8 ?? ?? ?? ?? a3 ?? ?? ?? ?? 68 e8 d8 02 9a 68 5d 33 78 df 8b 4d fc 51 e8 ?? ?? ?? ?? a3 ?? ?? ?? ?? 68 68 3c 59 02 68 78 33 78 df 8b 55 fc}  //weight: 1, accuracy: Low
        $x_1_2 = {c1 e9 02 85 c9 74 0b 31 06 83 c6 04 c1 c0 03 49 eb f1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Virus_WinNT_Cutwail_C_2147642400_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:WinNT/Cutwail.gen!C"
        threat_id = "2147642400"
        type = "Virus"
        platform = "WinNT: WinNT"
        family = "Cutwail"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {85 c9 74 09 30 06 46 c1 c0 03 49 eb f3}  //weight: 1, accuracy: High
        $x_1_2 = {68 da 84 ae 28 68 28 5f c3 d0 8b 45 fc 50 e8 ?? ?? ?? ?? a3 ?? ?? ?? ?? 68 e8 d8 02 9a 68 5d 33 78 df}  //weight: 1, accuracy: Low
        $x_1_3 = {89 45 e4 68 52 57 4e 44 8b 55 e4 52 8b 45 14 50 ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

