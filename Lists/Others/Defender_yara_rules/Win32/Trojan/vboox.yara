rule Trojan_Win32_vboox_RDA_2147846504_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/vboox.RDA!MTB"
        threat_id = "2147846504"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "vboox"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {81 ee 9b 00 00 00 01 1f 81 f1 15 00 00 00 89 ef 81 f1 8f 00 00 00 09 ce 81 c9 41 00 00 00 81 c9 1d 00 00 00 81 c7 94 00 00 00 81 f1 69 00 00 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

