rule VirTool_WinNT_Mader_B_2147595149_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Mader.B"
        threat_id = "2147595149"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Mader"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Driver: Started [" ascii //weight: 1
        $x_1_2 = "\\winnt\\explorer.exe" wide //weight: 1
        $x_1_3 = {0f 20 c0 25 ff ff fe ff 0f 22 c0}  //weight: 1, accuracy: High
        $x_1_4 = {43 6f 72 65 20 28 25 78 29 0a 00 55 8b ec 83 ec}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_WinNT_Mader_A_2147606637_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Mader.gen!A"
        threat_id = "2147606637"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Mader"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {33 c9 33 d2 8d 44 4d ?? 8a 10 81 e2 ff 00 ff ff 83 ea ?? 41 83 f9 ?? 66 89 10 7c e6 66 83 65 ?? 00 8d 45 ?? 50 8d 45 f8}  //weight: 5, accuracy: Low
        $x_5_2 = {74 44 80 7d ?? 3e 75 2f 80 7d ?? 74 75 29 80 7d ?? 6e 75 23 80 7d ?? 63 75 1d 80 7d ?? 61 75 17 80 7d ?? 63 75 11 80 7d ?? 68 75 0b 80 7d ?? 65 75 05 33 c0 40 eb 02}  //weight: 5, accuracy: Low
        $x_2_3 = {63 00 6f 00 72 00 65 00 2e 00 63 00 61 00 63 00 68 00 65 00 2e 00 64 00 73 00 6b 00 00 00}  //weight: 2, accuracy: High
        $x_2_4 = ">VmImgDescriptor" ascii //weight: 2
        $x_1_5 = "\\\\.\\ITNDriver" ascii //weight: 1
        $x_1_6 = ">FIXO" ascii //weight: 1
        $x_1_7 = ">INT" ascii //weight: 1
        $x_1_8 = ">XIT" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            ((1 of ($x_5_*))) or
            (all of ($x*))
        )
}

