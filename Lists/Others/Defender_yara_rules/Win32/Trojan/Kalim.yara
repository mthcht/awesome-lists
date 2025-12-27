rule Trojan_Win32_Kalim_MX_2147959500_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kalim.MX!MTB"
        threat_id = "2147959500"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kalim"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 ff 15 88 a1 ?? 00 89 45 d8 85 c0 75 24}  //weight: 1, accuracy: Low
        $x_1_2 = {77 21 0f b6 c1 46 83 e8 30 66 0f 6e c0 8a 06 f3 0f e6 c0 f2 0f 59 c2 f2 0f 59 d4 f2 0f 58 c8 3c 30 7d d8 3c 65}  //weight: 1, accuracy: High
        $x_5_3 = "kalim" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

