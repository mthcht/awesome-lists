rule Trojan_Win64_ClawHavoc_GZ_2147964655_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ClawHavoc.GZ!MTB"
        threat_id = "2147964655"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ClawHavoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {83 f9 03 0f 85 9a 00 00 00 48 8b b0 98 fd ff ff 48 3b b0 a8 fd ff ff 0f 84 e5 01 00 00 48 8d 8e 88 00 00 00 48 89 88 98 fd ff ff b9 88}  //weight: 2, accuracy: High
        $x_1_2 = "Automatic hardware driver update tool" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

