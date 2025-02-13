rule Trojan_Win32_Tovtaker_RB_2147838507_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tovtaker.RB!MTB"
        threat_id = "2147838507"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tovtaker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {99 be 64 00 00 00 f7 fe 0f b6 54 15 ?? 33 ca 88 4d ?? 66 0f be 45 ?? 0f b7 c8 51 8b 4d 0c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

