rule VirTool_Win64_Hratz_A_2147844683_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Hratz.A!MTB"
        threat_id = "2147844683"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Hratz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b 85 30 04 00 00 48 63 48 04 4c 89 b4 0d 30 04 00 00 48 8b 85 30 04 00 00 48 63 48 04 8d 91 ?? ?? ?? ?? 89 94 0d 2c 04 00 00 48 83 bd c0 04 00 00 00 0f 84}  //weight: 1, accuracy: Low
        $x_1_2 = {48 83 bd b0 00 00 00 10 4c 0f 43 85 98 00 00 00 48 8d ?? ?? ?? ?? ?? 48 83 bd d0 00 00 00 10 48 0f 43 95 b8 00 00 00 48 89 5c 24 40 4c 89 5c 24 38 4c 89 54 24 30 48 89 4c 24 28}  //weight: 1, accuracy: Low
        $x_1_3 = {48 c7 45 40 1f 00 00 00 0f 10 05 ae 05 01 00 0f 11 00 f2 0f 10 0d b3 05 01 00 f2 0f 11 48 10 0f b6 0d af 05 01 00 88 48 18 c6 40 19 00}  //weight: 1, accuracy: High
        $x_1_4 = {48 8b 08 48 63 51 04 f6 44 02 10 06 74 8a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

