rule Trojan_Win32_FireHooker_SX_2147952560_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FireHooker.SX!MTB"
        threat_id = "2147952560"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FireHooker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = {8b 5d 0c 8b cf c1 e9 ?? 8b c7 c1 e0 ?? 33 c8 8b c6 c1 e8 ?? 03 cf 83 e0 ?? 8b 04 83 8b 5d fc 03 c6 33 c8 2b d9}  //weight: 6, accuracy: Low
        $x_4_2 = {0f b7 58 12 0f b7 50 10 0f b7 48 16 0f b7 c3 39 85 e0 fe ff ff 72 2d 8b 85 e0 fe ff ff 8b 9d e4 fe ff ff 0f b7 c0}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

