rule Trojan_Win32_Djvu_NEAA_2147835617_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Djvu.NEAA!MTB"
        threat_id = "2147835617"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Djvu"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {03 fa d3 ea 89 55 f8 8b 45 c8 01 45 f8 8b 45 f8 33 c7 31 45 fc 89 35 ?? ?? ?? ?? 8b 45 f4 89 45 e4 8b 45 fc 29 45 e4 8b 45 e4 89 45 f4 8d 45 e0 e8 ?? ?? ?? ?? ff 4d dc 0f 85 d4 fe ff ff 8b 4d f4 8b 45 08 5f 89 08}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

