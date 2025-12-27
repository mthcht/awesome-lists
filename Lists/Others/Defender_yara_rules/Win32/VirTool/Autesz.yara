rule VirTool_Win32_Autesz_A_2147953326_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Autesz.A!MTB"
        threat_id = "2147953326"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Autesz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 f6 56 51 [0-18] 50 ?? ?? ?? ?? ?? 8b cf ?? ?? ?? ?? ?? 83 c4 10 85 c0 ?? ?? 85 f6}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 44 24 04 56 8b 74 24 10 85 c0 ?? ?? 56 ff 74 24 10 50 ff 35 f4 8e 4e 00 ?? ?? ?? ?? ?? ?? 5e c2 0c 00 8b 4e 10 81 f9 [0-16] 83 66}  //weight: 1, accuracy: Low
        $x_1_3 = "EnumerateDCs" ascii //weight: 1
        $x_1_4 = "Keylogger" ascii //weight: 1
        $x_1_5 = "SendLoggerData" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

