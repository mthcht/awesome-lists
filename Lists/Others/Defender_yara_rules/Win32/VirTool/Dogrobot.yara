rule VirTool_Win32_Dogrobot_L_2147624366_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Dogrobot.gen!L"
        threat_id = "2147624366"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Dogrobot"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c7 00 b4 67 00 00 8b 44 24 08 c7 00 92 a5 00 00 eb 10}  //weight: 1, accuracy: High
        $x_1_2 = {66 c7 45 ee 5c 00 66 c7 45 f0 61 00 66 c7 45 f2 74 00 66 c7 45 f4 61 00 66 c7 45 f6 70 00 66 c7 45 f8 69 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

