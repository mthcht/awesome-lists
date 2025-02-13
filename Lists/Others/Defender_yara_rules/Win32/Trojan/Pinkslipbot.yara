rule Trojan_Win32_Pinkslipbot_PA_2147734880_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Pinkslipbot.PA!MTB"
        threat_id = "2147734880"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Pinkslipbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 44 24 10 89 c8 89 54 24 0c f7 e6 8b 4c 24 0c 69 c9 ?? ?? ?? ?? 01 ca 8b 4c 24 10 8a 99 ?? ?? ?? 00 89 84 24 ?? ?? ?? ?? 89 94 24 ?? ?? ?? ?? 8b 84 24 ?? ?? ?? ?? 35 ?? ?? ?? ?? 8a 3c 0d ?? ?? ?? 00 28 df 88 7c 0c ?? 83 c1 01 66 c7 84 24 ?? ?? ?? ?? ?? ?? 39 c1 89 4c 24 ?? 74 ?? eb 17 00 8b 44 24 ?? 8b 8c 24 ?? ?? ?? ?? 8b 94 24 ?? ?? ?? ?? be}  //weight: 1, accuracy: Low
        $x_1_2 = {28 cd 88 6c 04 ?? 01 d0 83 f8 0e 89 44 24 ?? 0f 84 ?? ?? ?? ?? eb ?? 31 c0 8d 4c 24 ?? 89 4c 24 ?? 89 44 24 ?? eb 1f 00 8b 44 24 ?? 8a 0c 05 ?? ?? ?? 00 8b 94 24 ?? ?? ?? ?? 81 f2 ?? ?? ?? ?? 8a 2c 05}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Pinkslipbot_RPM_2147832970_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Pinkslipbot.RPM!MTB"
        threat_id = "2147832970"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Pinkslipbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 e8 8b 55 ec 01 02 8b 45 d8 03 45 b0 03 45 e8 89 45 b4 6a 00 e8 ?? ?? ?? ?? 03 45 b4 8b 55 ec 31 02 83 45 e8 04 83 45 ec 04 8b 45 e8 3b 45 e4 72 cd}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

