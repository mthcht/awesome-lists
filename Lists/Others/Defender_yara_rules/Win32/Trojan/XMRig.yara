rule Trojan_Win32_XMrig_CRHJ_2147847868_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/XMrig.CRHJ!MTB"
        threat_id = "2147847868"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "XMrig"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {88 45 d3 0f b6 4d d3 51 8d 4d e4 e8 ?? ?? ?? ?? 0f b6 10 69 d2 ?? ?? ?? ?? 83 e2 ?? 8b 45 08 03 45 d4 0f b6 08 33 ca 8b 55 08 03 55 d4 88 0a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

