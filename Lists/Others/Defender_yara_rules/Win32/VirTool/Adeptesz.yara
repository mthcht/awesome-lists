rule VirTool_Win32_Adeptesz_A_2147974408_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Adeptesz.A"
        threat_id = "2147974408"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Adeptesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 55 d4 89 54 24 08 c7 44 24 04 00 00 00 00 c7 04 24 00 00 00 00 ff ?? 83 ec 18 89 45 cc 83 7d cc 00 ?? ?? ?? ?? ?? ?? 8b 45 cc 01 c0 89 04 24 e8 ?? ?? ?? ?? 89 85 54 ff ff ff 8b 85 54 ff ff ff 85 c0}  //weight: 1, accuracy: Low
        $x_1_2 = {89 7c 24 1c 89 74 24 18 89 5c 24 14 89 4c 24 10 c7 44 24 0c 01 00 00 00 c7 44 24 08 03 00 00 00 8b 4d d0 89 4c 24 04 89 14 24 89 c1 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

