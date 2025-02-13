rule Trojan_Win32_Chinky_MBWM_2147929948_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Chinky.MBWM!MTB"
        threat_id = "2147929948"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Chinky"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {19 40 00 02 00 b7 01 68 [0-15] 1a 40 00 88 95}  //weight: 1, accuracy: Low
        $x_2_2 = {64 17 40 00 20 13 40 00 04 f8 30 01 00 ff ff ff 08 00 00 00 01 00 00 00 02 00 00 00 e9 00 00 00 80 12 40 00 b4 11 40 00 70 11 40 00 78 00 00 00 81 00 00 00 8a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

