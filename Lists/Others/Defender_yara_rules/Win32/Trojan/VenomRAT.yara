rule Trojan_Win32_VenomRAT_BAA_2147957280_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VenomRAT.BAA!MTB"
        threat_id = "2147957280"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VenomRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 55 08 03 55 fc 0f be 0a 8b 45 fc 33 d2 be 23 00 00 00 f7 f6 0f be 92 ?? ?? ?? ?? 33 ca 8b 45 08 03 45 fc 88 08 eb c7}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

