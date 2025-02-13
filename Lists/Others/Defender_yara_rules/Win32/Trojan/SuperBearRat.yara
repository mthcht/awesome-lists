rule Trojan_Win32_SuperBearRat_AVKF_2147890053_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuperBearRat.AVKF!MTB"
        threat_id = "2147890053"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuperBearRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {51 68 00 04 00 00 8b 55 b4 52 8b 45 c0 8b 08 51}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

