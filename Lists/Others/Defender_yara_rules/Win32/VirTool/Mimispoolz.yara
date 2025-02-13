rule VirTool_Win32_Mimispoolz_A_2147793782_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Mimispoolz.A!MTB"
        threat_id = "2147793782"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Mimispoolz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 68 ff 01 0f 00 ff 15 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? 85 c0 0f 84 ?? ?? ?? ?? 8d 44 ?? ?? 50 6a 01 6a 01 55 68 00 00 00 02 ff 74 24 30 ff 15 ?? ?? ?? ?? 8b 35 ?? ?? ?? ?? 85 c0 0f 84 ?? ?? ?? ?? 55 ff 74 24 10 8d 44 ?? ?? 50 ff 15 ?? ?? ?? ?? 85 c0}  //weight: 1, accuracy: Low
        $x_1_2 = {50 6a 0c ff 74 24 1c ff 15 ?? ?? ?? ?? 85 c0 ?? ?? 8d 44 ?? ?? 50 8d 44 ?? ?? 50 55 ff 74 24 28 68 10 04 00 00 55 55 55 55 68 ?? ?? ?? ?? ff 74 24 38 ff 15 ?? ?? ?? ?? 85 c0}  //weight: 1, accuracy: Low
        $x_1_3 = {63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 00 00 77 00 69 00 6e 00 73 00 74 00 61 00 30 00 5c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

