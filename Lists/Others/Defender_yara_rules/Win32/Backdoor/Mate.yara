rule Backdoor_Win32_Mate_NK_2147963842_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Mate.NK!MTB"
        threat_id = "2147963842"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Mate"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c6 07 00 ff 15 c4 30 41 00 8b f0 85 f6 0f 84 83 00 00 00 8b 45 04 56 50 ff 15 c0 30 41 00 8b d8 8b 45 04 56 50 ff 15 bc 30 41 00 8b f0 85 f6 89 74 24 10 74 61 56 ff 15 b8 30 41 00 8a 4c 18 ff 84 c9 74 35}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

