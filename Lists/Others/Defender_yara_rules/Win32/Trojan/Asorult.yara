rule Trojan_Win32_Asorult_BB_2147741211_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Asorult.BB!MTB"
        threat_id = "2147741211"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Asorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {85 c0 75 14 a1 ?? ?? ?? ?? b9 ?? ?? ?? ?? 03 c8 03 c3 8a 14 19 88 14 30 a1 ?? ?? ?? ?? 8a 0d ?? ?? ?? ?? 03 c3 03 c6 8a 10 32 d1 43 81 fb da 04 00 00 88 10 7e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

