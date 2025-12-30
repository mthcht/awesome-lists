rule Trojan_Win64_RokRat_A_2147960226_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/RokRat.A!MTB"
        threat_id = "2147960226"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "RokRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {0f 1f 40 00 66 66 66 0f 1f 84 00 00 00 00 00 0f b6 04 11 34 fa 88 01 48 8d 49 01 49 83 e8 01 75}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

