rule VirTool_Win32_Berentesz_A_2147919109_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Berentesz.A!MTB"
        threat_id = "2147919109"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Berentesz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 6a 00 6a 00 6a 00 6a 00 50 6a 01 6a 01 6a 01 68 3f 00 0f 00 [0-16] ff 37 ?? ?? ?? ?? ?? ?? 8b 4d f0 89 47 04 83 f9 0f}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 00 68 80 00 00 00 6a 02 6a 00 6a 00 68 00 00 00 40 50 ?? ?? ?? ?? ?? ?? 8b 4d e4 8b f0 83 f9 0f}  //weight: 1, accuracy: Low
        $x_1_3 = {bf c0 a0 00 00 6a 00 0f 45 f9 ?? ?? ?? 50 ba 58 80 40 00 b9 18 21 41 00 57 0f 44 ca 51 56 ?? ?? ?? ?? ?? ?? 56 85 c0}  //weight: 1, accuracy: Low
        $x_1_4 = {6a 02 6a 00 6a 00 ?? ?? ?? ?? ?? ?? 89 03 85 c0 ?? ?? 68 ff 01 0f 00 ?? ?? ?? ?? ?? 50 ?? ?? ?? ?? ?? ?? 89 43 04 85 c0 ?? ?? ?? ?? ?? 51 6a 01 50 ?? ?? ?? ?? ?? ?? 85 c0 ?? ?? ff 73 04}  //weight: 1, accuracy: Low
        $x_1_5 = {83 78 14 0f ?? ?? 8b 00 50 ?? ?? ?? ?? ?? ?? 8b 4d d0 8a d8 83 f9 0f ?? ?? 8b 55 bc 41 8b c2 81 f9 00 10 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

