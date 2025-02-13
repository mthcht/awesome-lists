rule VirTool_Win32_DripLoz_A_2147781569_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/DripLoz.A!MTB"
        threat_id = "2147781569"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DripLoz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {05 c1 00 00 00 0f 05 48 83 f8 00 ?? ?? 49 8b cc 49 8b d5 4d 8b c6 4d 8b cf 4c 8b d1 48 33 c0 05 bd 00 00 00 0f 05 48 83 f8 00 ?? ?? ?? ?? ?? ?? 49 8b cc 49 8b d5 4d 8b c6 4d 8b cf 4c 8b d1 48 33 c0 05 bc 00 00 00 0f 05 48 83 f8 00}  //weight: 1, accuracy: Low
        $x_1_2 = {4d 8b c2 49 c7 c2 01 00 00 00 4d 33 d2 49 c7 c2 0a 00 00 00 4c 8b d1 33 c0 4d 2b c2 83 c0 18 4d 33 c0 0f 05 c3 48 83 c1 0a 33 c0 4c 8b d1 83 c0 3a 49 83 ea 0a 48 83 e9 0a 0f 05 c3 49 83 c2 1c 33 c0 4c 8b d1 49 83 ea 01 83 c0 50 49 83 c2 01 0f 05 c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

