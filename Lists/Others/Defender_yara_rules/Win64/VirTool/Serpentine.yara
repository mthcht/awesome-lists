rule VirTool_Win64_Serpentine_B_2147772376_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Serpentine.B!MTB"
        threat_id = "2147772376"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Serpentine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\svchost.exe" wide //weight: 1
        $x_1_2 = "rs.ps1" wide //weight: 1
        $x_1_3 = "/C PowerShell.exe -ExecutionPolicy Bypass -File" wide //weight: 1
        $x_1_4 = {ba 02 00 00 00 48 8d ?? ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 48 8d ?? ?? ?? ?? ?? 48 8d ?? ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 45 33 c0 48 8d ?? ?? ?? ?? ?? 48 8d ?? ?? ff 15 ?? ?? ?? ?? 48 c7 85 e8 04 00 00 00 00 00 00 4c 8d ?? ?? ?? ?? ?? 48 8d ?? ?? ?? ?? ?? 48 c7 c1 01 00 00 80 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

