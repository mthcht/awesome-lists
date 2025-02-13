rule Trojan_Win64_Filesponger_EN_2147851363_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Filesponger.EN!MTB"
        threat_id = "2147851363"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Filesponger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {41 b9 40 00 00 00 41 b8 00 30 00 00 ba 10 a8 27 00 33 c9}  //weight: 5, accuracy: High
        $x_5_2 = {45 33 c9 45 33 c0 ba a0 c5 7f 00}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

