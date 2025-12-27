rule HackTool_Win64_Defenderwrite_A_2147956012_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/Defenderwrite.A"
        threat_id = "2147956012"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Defenderwrite"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "DefenderWrite: The tool used to drop files into the Antivirus folder." ascii //weight: 2
        $x_2_2 = "Usage: DefenderWrite.exe <TargetExePath> <FullDLLPath> <FileToWrite>" ascii //weight: 2
        $x_1_3 = "WriteProcessMemory for arguments failed" ascii //weight: 1
        $x_1_4 = "RunMe run successfully" ascii //weight: 1
        $x_1_5 = "Injection failed" ascii //weight: 1
        $x_1_6 = "/TwoSevenOneT" ascii //weight: 1
        $x_2_7 = {48 83 7e 18 07 76 03 4c 8b 06 33 db 48 89 5c 24 20 4d 8b cf 49 8b d5 49 8b ce ff 15 ?? ?? ?? ?? 85 c0 0f 84 ?? ?? 00 00 4c 8b c7 48 83 7f 18 07 76 03 4c 8b 07 48 89 5c 24 20 4c 8b ?? 49 8b d4 49 8b ce ff 15}  //weight: 2, accuracy: Low
        $x_2_8 = {c7 44 24 20 04 00 00 00 41 b9 00 10 00 00 4d 8b c7 33 d2 ff 15 ?? ?? ?? ?? 4c 8b e8 c7 44 24 20 04 00 00 00 41 b9 00 10 00 00 4c 8b c3 33 d2 49 8b ce ff 15}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

