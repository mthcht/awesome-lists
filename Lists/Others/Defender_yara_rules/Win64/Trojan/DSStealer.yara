rule Trojan_Win64_DSStealer_MCU_2147964771_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DSStealer.MCU!MTB"
        threat_id = "2147964771"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DSStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {f7 d2 81 c1 c6 72 22 29 d3 ca 41 89 c0 81 f2 c6 72 22 29 0f ca b8 01 00 00 00 29 d0 0f c8}  //weight: 1, accuracy: High
        $x_1_2 = {ca 07 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 40 2e 67 78 66 67 00 00 00 50 15 00 00 00 30 08 00 00 16 00 00 00 e6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

