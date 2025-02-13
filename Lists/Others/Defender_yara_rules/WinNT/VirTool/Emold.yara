rule VirTool_WinNT_Emold_A_2147610390_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Emold.gen!A"
        threat_id = "2147610390"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Emold"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "41"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "NtWriteVirtualMemory" ascii //weight: 10
        $x_10_2 = "NtProtectVirtualMemory" ascii //weight: 10
        $x_10_3 = "KeServiceDescriptorTable" ascii //weight: 10
        $x_10_4 = "\\SystemRoot\\system32\\ntdll.dll" wide //weight: 10
        $x_1_5 = {8b 45 fc 0f b7 08 8b c1 66 25 00 f0 66 3d 00 30 75 ?? 81 e1 ff 0f 00 00 03 0e 8b 04 19 03 c2}  //weight: 1, accuracy: Low
        $x_1_6 = {fa 0f 20 c0 8b c0 89 45 ?? 8b db 25 ff ff fe ff 0f 22 c0 8b 45 ?? 8b 55 ?? 8b db f0}  //weight: 1, accuracy: Low
        $x_1_7 = {25 ff ff fe ff 0f 22 c0 8b 45 ?? 8b 55 ?? ?? ?? f0 87 10 ?? ?? 8b 45 ?? 0f 22 c0 fb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_WinNT_Emold_B_2147628257_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Emold.B"
        threat_id = "2147628257"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Emold"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 45 4d 4f 00 50 6a 01 ff 15}  //weight: 1, accuracy: High
        $x_1_2 = {8a d0 80 c2 15 30 14 30 40 3b c1 7c f3}  //weight: 1, accuracy: High
        $x_1_3 = {fa 0f 20 c0 8b d2 89 44 ?? ?? 8b d2 25 ff ff fe ff 0f 22 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_WinNT_Emold_C_2147628327_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Emold.C"
        threat_id = "2147628327"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Emold"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {5e 73 44 7d 6b 6c 72 7f 78 5a}  //weight: 2, accuracy: High
        $x_2_2 = {8b b4 3b a0 00 00 00 03 df 68}  //weight: 2, accuracy: High
        $x_1_3 = {30 14 30 40 3b c1 7c}  //weight: 1, accuracy: High
        $x_1_4 = {30 14 30 83 c0 01 3b c1 7c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

