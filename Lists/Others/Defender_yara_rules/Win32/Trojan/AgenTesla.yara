rule Trojan_Win32_AgenTesla_RT_2147743231_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AgenTesla.RT!MTB"
        threat_id = "2147743231"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AgenTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {bb 00 01 00 00 01 d8 89 c6 f7 db [0-4] 89 df [0-6] 50 58 8b 04 0a [0-6] 01 f3 0f ef c0 0f ef c9 [0-6] 0f 6e c0 [0-4] 0f 6e 0b [0-6] 0f ef c1 51 50 58 0f 7e c1 [0-4] 88 c8 [0-4] 59 [0-4] 29 f3 83 c3 01 75 ?? 50 58 89 fb [0-6] [0-16] 89 04 0a [0-48] 83 c1 01 75 b3}  //weight: 1, accuracy: Low
        $x_1_2 = {50 58 51 59 ff e0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

