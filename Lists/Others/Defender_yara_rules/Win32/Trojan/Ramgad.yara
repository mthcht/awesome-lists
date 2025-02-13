rule Trojan_Win32_Ramgad_A_2147649935_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ramgad.A"
        threat_id = "2147649935"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ramgad"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {bb 01 00 00 00 8b 06 8a 44 18 ff 04 ?? 2c ?? 72 06 04 9b 2c 20 73 15 8b c6 e8 ?? ?? ?? ?? 8b 16 0f b6 54 1a ff 83 ea 20 88 54 18 ff 43 4f 75}  //weight: 2, accuracy: Low
        $x_1_2 = "U2xvY2suZGxs" ascii //weight: 1
        $x_1_3 = "R2V0TGlzdD1OdW1iZXJUaHJlYWRz" ascii //weight: 1
        $x_1_4 = "TXkgbmFtZSBpcyBBcm1hZ2VkZG9OLCBpIGtpbGwgeW91IHdlYnNpdGUgOyk=." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Ramgad_B_2147652528_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ramgad.B"
        threat_id = "2147652528"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ramgad"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8d 40 00 53 81 c4 04 f0 ff ff 50 83 c4 f8 8b d8 c7 04 24 00 10 00 00 54 8d 44 24 08 50 e8}  //weight: 2, accuracy: High
        $x_2_2 = "QXJtYWdlZGRvTg==" ascii //weight: 2
        $x_2_3 = "TXkgbmFtZSBpcyBBcm1hZ2VkZG9" ascii //weight: 2
        $x_2_4 = "Li4uOjo6QXJtYWdlZGRvTjo6Oi4uLg==" ascii //weight: 2
        $x_2_5 = "R2V0TGlzdD1" ascii //weight: 2
        $x_2_6 = "U1lTVEVNXEN" ascii //weight: 2
        $x_2_7 = "U29mdHdhcmVcTWljcm9zb2Z0XFdpbmRvd3" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

