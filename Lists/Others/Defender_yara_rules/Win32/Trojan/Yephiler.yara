rule Trojan_Win32_Yephiler_DA_2147961556_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Yephiler.DA!MTB"
        threat_id = "2147961556"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Yephiler"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f b6 8c 0d [0-2] ff ff 01 c8 b9 00 01 00 00 99 f7 f9 0f b6 b4 15 [0-2] ff ff 8b 45 08 8b 8d [0-2] ff ff 0f b6 14 08 31 f2 88 14 08 8b 85 [0-2] ff ff 83 c0 01 89 85 [0-2] ff ff e9}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

