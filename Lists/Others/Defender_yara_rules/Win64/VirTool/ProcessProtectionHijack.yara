rule VirTool_Win64_ProcessProtectionHijack_A_2147935717_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/ProcessProtectionHijack.A"
        threat_id = "2147935717"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "ProcessProtectionHijack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 83 ec 28 0f b6 d1 ?? ?? ?? ?? ?? ?? ?? 8b c2 83 e0 0f 48 63 c8 41 8b 84 88 4c 36 00 00 49 03 c0}  //weight: 1, accuracy: Low
        $x_1_2 = {4c 89 7c 24 58 48 8b cb 48 89 44 24 50 f3 0f 7f 44 24 64 44 89 7c 24 74 c7 44 24 60 04 00 00 00 e8}  //weight: 1, accuracy: High
        $x_1_3 = {4c 89 7c 24 48 4c 89 7c 24 58 4d 8b f0 f3 0f 7f 44 24 64 44 89 7c 24 74 48 8b ea 48 8b d9 c7 44 24 60 04 00 00 00 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

