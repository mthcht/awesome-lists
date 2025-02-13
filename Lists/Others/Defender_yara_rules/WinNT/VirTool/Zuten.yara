rule VirTool_WinNT_Zuten_A_2147600462_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Zuten.A"
        threat_id = "2147600462"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Zuten"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 75 10 6a 05 56 e8 ?? ?? ff ff 2b de 83 c3 0b c6 06 e9 89 5e 01 8b 4d 2c ff 15}  //weight: 2, accuracy: Low
        $x_3_2 = {5c 44 6f 73 44 65 76 69 63 65 73 5c 63 3a 5c 6e 61 6d 65 2e 6c 6f 67 00}  //weight: 3, accuracy: High
        $x_3_3 = {84 21 10 80 75}  //weight: 3, accuracy: High
        $x_2_4 = "GameHack\\" ascii //weight: 2
        $x_1_5 = {4b 65 53 65 72 76 69 63 65 44 65 73 63 72 69 70 74 6f 72 54 61 62 6c 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule VirTool_WinNT_Zuten_B_2147600521_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Zuten.B"
        threat_id = "2147600521"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Zuten"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {83 c3 0b c6 06 e9 89 5e 01 8b 4d 2c ff 15}  //weight: 1, accuracy: High
        $x_1_2 = {c6 45 e6 8d c6 45 e7 45 c6 45 e8 08 c6 45 e9 50 c6 45 ea 6a c6 45 eb 09 c6 45 ec 6a c6 45 ed fe c6 45 ef 15}  //weight: 1, accuracy: High
        $x_1_3 = {c6 45 ea 8d c6 45 eb 45 c6 45 ec 08}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule VirTool_WinNT_Zuten_C_2147601306_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Zuten.C"
        threat_id = "2147601306"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Zuten"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "KeServiceDescriptorTable" ascii //weight: 2
        $x_2_2 = "\\objfre\\i386\\hookdll.pdb" ascii //weight: 2
        $x_2_3 = {00 67 6e 61 69 78 6e 61 75 68 71 71 00}  //weight: 2, accuracy: High
        $x_2_4 = {00 6e 61 69 78 75 68 7a 00}  //weight: 2, accuracy: High
        $x_1_5 = {00 6e 69 6c 75 77 00}  //weight: 1, accuracy: High
        $x_2_6 = {8b c0 8b c0 8b c0 90 90 90 90}  //weight: 2, accuracy: High
        $x_2_7 = {8b 75 10 6a 05 56 e8 ?? ?? ff ff 2b de 83 c3 0b c6 06 e9 89 5e 01 8b 4d 2c ff 15}  //weight: 2, accuracy: Low
        $x_2_8 = {60 e8 00 00 00 00 5f 81 e7 00 ff ff ff 8d 77 ?? eb 09 80 3e ?? 75 03 80 36 ?? 46 80 3e 00 75 f2 8d 77 ?? eb 0c 56 ff 17 eb 01 46 80 3e 00 75 fa 46 66 83 3e 00 75 ee}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule VirTool_WinNT_Zuten_D_2147601556_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Zuten.gen!D"
        threat_id = "2147601556"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Zuten"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {5c 47 61 6d 65 48 61 63 6b 5c [0-20] 5c 6f 62 6a 66 72 65 5c 69 33 38 36 5c [0-16] 2e 70 64 62 00}  //weight: 2, accuracy: Low
        $x_2_2 = {00 00 5c 00 44 00 6f 00 73 00 44 00 65 00 76 00 69 00 63 00 65 00 73 00 5c 00 63 00 3a 00 5c 00 6e 00 61 00 6d 00 65 00 2e 00 6c 00 6f 00 67 00 00 00}  //weight: 2, accuracy: High
        $x_1_3 = "RAS Asynchronous Media Driver" wide //weight: 1
        $x_1_4 = "\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\AsyncMac" wide //weight: 1
        $x_1_5 = "ZwCreateFile" ascii //weight: 1
        $x_2_6 = {56 56 68 00 04 00 00 08 00 90 90 8b c0 90 8b c0 90}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

