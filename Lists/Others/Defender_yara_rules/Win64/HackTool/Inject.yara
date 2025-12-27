rule HackTool_Win64_Inject_SX_2147959607_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/Inject.SX!MTB"
        threat_id = "2147959607"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Inject"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "Low"
    strings:
        $x_15_1 = {48 89 01 48 8b 0d da 54 0d ?? ?? ?? ?? 89 0a f3 0f 6f 05 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 41 0f 11 00 f3 0f 6f 0d ?? ?? ?? ?? 41 0f 11 48 10 49 89 01 8b 05 ?? ?? ?? ?? 41 89 41 08 31 c0}  //weight: 15, accuracy: Low
        $x_10_2 = {66 0f 7e ca 66 0f 6f c1 48 8b 84 24 e8 00 00 00 48 2b 84 24 e0 00 00 00 48 89 84 24 90 00 00 00 66 49 0f 6e ec 44 89 e0 48 8d 34 12 66 0f 6c c5 48 8d 54 06 08 48 8d 8c 24 e0 00 00 00 48 89 84 24 88 00 00 00 0f c6 c0 e8 66 0f d6 84 24 98 00 00 00}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

