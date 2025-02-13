rule Trojan_Win64_RecordBreaker_EC_2147841725_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/RecordBreaker.EC!MTB"
        threat_id = "2147841725"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "RecordBreaker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_7_1 = {31 c0 44 89 ca 41 33 14 80 88 14 01 48 ff c0 48 83 f8 0e 75 ed}  //weight: 7, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

