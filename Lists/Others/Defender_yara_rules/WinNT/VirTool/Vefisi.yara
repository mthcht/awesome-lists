rule VirTool_WinNT_Vefisi_A_2147597815_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Vefisi.gen!A"
        threat_id = "2147597815"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Vefisi"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {bb 44 64 6b 20 53 bf 00 02 00 00 57 6a 01 ff d6 8b 4d 10 80 21 00 ff 75 08 80 20 00 89 45 fc}  //weight: 1, accuracy: High
        $x_1_2 = {8b 5c 24 08 56 8b c3 57 8d 50 01 8a 08 40 84 c9 75 f9 8b 7c 24 18 57 ff 74 24 18 2b c2 8d 34 18 56}  //weight: 1, accuracy: High
        $x_1_3 = {6b 69 6c 6c 00 00 00 6b 77 61 74 63 68 00 00 53 79 73 74 65 6d 00 55 8b ec 81 ec 1c 06}  //weight: 1, accuracy: High
        $x_5_4 = {fa 0f 20 c0 25 ff ff fe ff 0f 22 c0 8b 0d ?? ?? 01 00 8b 31 a1 ?? ?? 01 00 8b 50 01 8b 14 96 89 15 ?? ?? 01 00 8b 40 01 8b 09 c7 04 81}  //weight: 5, accuracy: Low
        $x_3_5 = {01 00 0f 20 c0 0d 00 00 01 00 0f 22 c0 fb}  //weight: 3, accuracy: High
        $x_2_6 = "ZwQueryDirectoryFile" ascii //weight: 2
        $x_2_7 = "ZwSetValueKey" ascii //weight: 2
        $x_2_8 = "KeServiceDescriptorTable" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_3_*) and 3 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_WinNT_Vefisi_H_2147597995_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Vefisi.H"
        threat_id = "2147597995"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Vefisi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {53 79 73 74 65 6d 00 56 33 f6 8b 44 24 08 6a 06 03 c6 50 68 00 03 01 00 ff 15 ?? ?? 01 00 83 c4 0c 85 c0 74 0f 46 81 fe 00 10 00 00 72 dc}  //weight: 4, accuracy: Low
        $x_1_2 = "SizeOfOldSids = %x" ascii //weight: 1
        $x_1_3 = {83 e8 fa 40 40 40 40 40 40}  //weight: 1, accuracy: High
        $x_2_4 = {8b 0c 19 68 44 64 6b 20 57 6a 01}  //weight: 2, accuracy: High
        $x_3_5 = {8b 4d 20 b8 14 80 7b 2a 3b c8 0f 87 ?? ?? 00 00 0f 84}  //weight: 3, accuracy: Low
        $x_4_6 = {25 77 73 0a 00 55 8b ec 83 ec 34 53 56 8b 75 24 57 33 ff 89 7d fc 89 3e 89 7e 04}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*))) or
            ((2 of ($x_4_*))) or
            (all of ($x*))
        )
}

