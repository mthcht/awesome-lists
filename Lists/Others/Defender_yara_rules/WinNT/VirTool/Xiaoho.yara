rule VirTool_WinNT_Xiaoho_2147630699_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Xiaoho"
        threat_id = "2147630699"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Xiaoho"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\DosDevices\\KPDrvLN1" ascii //weight: 1
        $x_1_2 = "HAL.dll" ascii //weight: 1
        $x_1_3 = {83 ec 40 56 57 c7 ?? ?? 10 00 00 c0 [0-64] 81 ?? ?? c0 20 22 00 74 05 e9 b1 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = {56 64 a1 24 c7 45 ?? 01 00 00 8b c7 45 ?? 74 24 08 3b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

