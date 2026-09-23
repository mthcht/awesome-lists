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

rule VirTool_Win32_Autesz_A_2147978707_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Autesz.A"
        threat_id = "2147978707"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Autesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 6a 02 57 ff ?? ?? ?? ?? ?? 85 c0 ?? ?? ?? ?? ?? ?? ?? ?? 50 6a 02 ff b5 c4 fd ff ff ff ?? ?? ?? ?? ?? 85 c0 ?? ?? ff}  //weight: 1, accuracy: Low
        $x_1_2 = {50 6a 40 89 8d a0 ed ff ff 89 85 ?? ed ff ff ff ?? ?? ?? ?? ?? 89 85 a4 ed ff ff 85 c0 [0-18] e8 ?? ?? ?? ?? 83 c4 08 85 db ?? ?? ?? ?? ?? ?? ff}  //weight: 1, accuracy: Low
        $x_1_3 = {56 ff 73 60 6a 01 ff 73 64 ff ?? ?? ?? ?? ?? 56 ff ?? ?? ?? ?? ?? 83 c4 14 ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? 83 c4 04 [0-16] e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

