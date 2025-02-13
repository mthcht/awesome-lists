rule Trojan_Win32_OrcusRat_MBXQ_2147918550_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OrcusRat.MBXQ!MTB"
        threat_id = "2147918550"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OrcusRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {89 11 a4 02 42 00 00 08 31 08 a1 ?? ?? ?? 00 08 00 c8 eb 56 00}  //weight: 3, accuracy: Low
        $x_2_2 = {64 1b 40 00 00 f0 30 00 00 ff ff ff 08 00 00 00 01 00 00 00 03 00 00 00 e9 00 00 00 d0 15 40 00 d8 14 40 00 f0 13 40 00 78 00 00 00 80}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

