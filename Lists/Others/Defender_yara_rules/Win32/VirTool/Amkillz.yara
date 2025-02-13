rule VirTool_Win32_Amkillz_B_2147844672_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Amkillz.B!MTB"
        threat_id = "2147844672"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Amkillz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c6 45 ee 48 c6 45 ef 3f c6 45 f0 3f c6 45 f1 3f c6 45 f2 3f c6 45 f3 74 c6 45 f4 33 c7 45 d8 11 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {50 8b 45 d8 50 8d 4d ?? 51 68 00 04 00 00 8d 95 ?? ?? ?? ?? 52 e8}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 45 08 03 45 f8 0f b6 08 ba 01 00 00 00 6b c2 00 8b 55 10 0f b6 04 02 3b c8}  //weight: 1, accuracy: High
        $x_1_4 = {8b 85 84 fb ff ff 50 8b 4d c0 51 ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

