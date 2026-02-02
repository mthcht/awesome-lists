rule VirTool_Win64_Injesez_A_2147962167_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Injesez.A"
        threat_id = "2147962167"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Injesez"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c2 c1 e0 05 48 63 c8 48 03 cb 80 39 4c ?? ?? 80 79 01 8b ?? ?? 80 79 02 d1 ?? ?? 80 79 03 b8}  //weight: 1, accuracy: Low
        $x_1_2 = {4c 89 6c 24 70 48 c7 45 60 00 10 00 00 c7 44 24 28 40 00 00 00 c7 44 24 20 00 30 00 00 ?? ?? ?? ?? 45 33 c0 ?? ?? ?? ?? ?? 48 8b ce e8 ?? ?? ?? ?? 85 c0 ?? ?? 8b d0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

