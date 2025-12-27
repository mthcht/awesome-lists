rule VirTool_Win64_Autesz_A_2147953325_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Autesz.A!MTB"
        threat_id = "2147953325"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Autesz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 8b cf 48 8d ?? ?? ?? ?? ?? ?? 41 83 c9 01 48 89 44 24 20 45 33 c0 ?? ?? ?? ?? ?? ?? ?? 48 8b ce ?? ?? ?? ?? ?? ?? 85 c0 ?? ?? ?? ?? ?? ?? 48 8b 8c 24 b0 03 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 48 89 44 24 28}  //weight: 1, accuracy: Low
        $x_1_2 = {4c 8b ce 4d 8b c4 41 8b d5 48 8b cd ?? ?? ?? ?? ?? ?? 48 8b 9c 24 d8 00 00 00 41 bc ?? ?? 00 00 48 8b f0 49 3b dc ?? ?? ?? ?? ?? ?? 48 8b 8c 24 c8 00 00 00 41 b8 ?? ?? ?? ?? 45 0f}  //weight: 1, accuracy: Low
        $x_1_3 = "EnumerateDCs" ascii //weight: 1
        $x_1_4 = "Keylogger" ascii //weight: 1
        $x_1_5 = "SendLoggerData" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

