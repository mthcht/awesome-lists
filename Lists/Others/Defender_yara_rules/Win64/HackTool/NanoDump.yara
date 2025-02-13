rule HackTool_Win64_NanoDump_LK_2147895701_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/NanoDump.LK!MTB"
        threat_id = "2147895701"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "NanoDump"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 01 d0 0f b7 00 66 89 45 f6 0f b7 45 f6 8b 55 f8 c1 ca 08 01 d0 31 45 f8 8b 55 fc 48 8b 45 10 48 01 d0 0f b6 00 84 c0 75 c7}  //weight: 1, accuracy: High
        $x_1_2 = {48 8b 45 d0 0f b6 08 48 8b 55 b8 8b 45 f4 48 98 48 01 d0 89 ca 88 10 48 83 45 f8 02 83 45 f4 01}  //weight: 1, accuracy: High
        $x_1_3 = {88 05 7e 8c 08 00 8b 45 fc 48 63 d0 48 8b 45 10 48 01 d0 44 0f b6 00 0f b6 4d fb 8b 45 fc 48 63 d0 48 8b 45 10 48 01 d0 44 89 c2 31 ca 88 10 83 45 fc 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

