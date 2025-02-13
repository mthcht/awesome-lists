rule VirTool_Win32_Reviver_A_2147755222_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Reviver.A!MTB"
        threat_id = "2147755222"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Reviver"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff 15 5f 4e 01 00 48 8b c8 48 8d 45 a0 48 89 44 24 20 41 b9 ?? 00 00 00 4c 8d 45 20 48 8b d7}  //weight: 1, accuracy: Low
        $x_1_2 = {ff 15 38 4e 01 00 0f b6 45 20 ?? ?? ?? ?? ?? ?? ?? ?? ?? 44 24 39 0f b6 45 22 88 44 24 3a ?? ?? ?? ?? ?? ?? ?? ?? ?? b6 45 24 88 44 24 30 0f b6 45 25 88 44 24 31 [0-16] 45 27 88 44 24 33 48 63 [0-16] 34 33 49 8d 4e 09}  //weight: 1, accuracy: Low
        $x_1_3 = {48 8d 15 27 ce 01 00 48 8b c8 ff 15 56 4a 01 00 48 85 c0 75 09 48 8d 0d 22 ce 01 00 eb 25}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

