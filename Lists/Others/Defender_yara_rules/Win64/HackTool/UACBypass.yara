rule HackTool_Win64_UACBypass_AHB_2147961487_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/UACBypass.AHB!MTB"
        threat_id = "2147961487"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "UACBypass"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "50"
        strings_accuracy = "High"
    strings:
        $x_30_1 = {48 8b 8d 00 02 00 00 48 8b 95 f0 01 00 00 49 89 c8 4c 89 c7 48 89 d1 f3 aa 48 89 ca 49 89 f8}  //weight: 30, accuracy: High
        $x_20_2 = {c7 45 fc 22 00 00 c0 c7 45 f8 05 40 00 80 c7 45 f4 00 00 00 00 48 c7 45 e8 00 00 00 00}  //weight: 20, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

