rule Trojan_Win32_ColoredLambert_MFP_2147788158_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ColoredLambert.MFP!MTB"
        threat_id = "2147788158"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ColoredLambert"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c1 ef 05 8b d8 c1 e3 04 33 fb 8b 5d fc 83 e3 03 03 3c 9e 8b 5d fc 81 6d fc 47 86 c8 61 33 d8 03 d9 8d 0c 3b 8b f9 c1 ef 05 8b d9 c1 e3 04 33 fb 8b 5d fc c1 eb 0b 83 e3 03 03 3c 9e 8b 5d fc 33 d9 03 d8 8d 04 3b 39 55 fc 75}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

