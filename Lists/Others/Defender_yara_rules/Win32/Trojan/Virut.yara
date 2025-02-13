rule Trojan_Win32_Virut_AVI_2147907810_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Virut.AVI!MTB"
        threat_id = "2147907810"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Virut"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {57 b7 6f c5 20 ba 2b e1 8d 1b fa 85 ee 1f 53 ef 34 a2 cf 56}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Virut_MBXP_2147918549_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Virut.MBXP!MTB"
        threat_id = "2147918549"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Virut"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3c 51 41 00 06 f9 36 00 00 ff ff ff 08 00 00 00 01 00 00 00 01 00 00 00 e9 00 00 00 [0-6] 4f 41 00 fc 17 40 00 78 00 00 00 80 00 00 00 85 00 00 00 86 [0-25] 57 49 4e 44 4f 57 53}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

