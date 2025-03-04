rule Trojan_Win32_ParallaxRat_CCEE_2147896974_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ParallaxRat.CCEE!MTB"
        threat_id = "2147896974"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ParallaxRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {fe c3 8a 94 1d ?? ?? ?? ?? 02 c2 8a 8c 05 ?? ?? ?? ?? 88 8c 1d}  //weight: 1, accuracy: Low
        $x_1_2 = {30 0e 46 4f 0f 85}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ParallaxRat_APA_2147917660_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ParallaxRat.APA!MTB"
        threat_id = "2147917660"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ParallaxRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {68 13 02 00 00 6a 00 6a 00 6a 00 6a 00 8b 45 ec 50 8b 55 f4 8b 45 fc 8b 80 90 00 00 00 e8 76 34 fb ff 50 e8 98 4d fa ff ff 4d f4 83 7d f4 ff}  //weight: 2, accuracy: High
        $x_1_2 = {8b ec 83 c4 f0 89 4d f4 89 55 f8 89 45 fc 68 fc 69 40 00 68 10 6a 40 00 e8 02 fa ff ff 89 45 f0 68 18 6a 40 00 e8 65 fc ff ff 8b 55 fc 89 02 68 28 6a 40 00 e8 56 fc ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

