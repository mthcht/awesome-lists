rule Trojan_Win64_SparkRat_RTS_2147926712_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/SparkRat.RTS!MTB"
        threat_id = "2147926712"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "SparkRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 b9 42 57 b3 bf 65 9c 7e 6a 48 ba a0 e3 b6 1f e5 d2 3e 1e 48 03 14 08 31 c9 48 ff e2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

