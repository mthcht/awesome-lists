rule Trojan_Win64_GoInject_CA_2147970125_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/GoInject.CA!MTB"
        threat_id = "2147970125"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "GoInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {0f b6 3c 02 31 f7 31 d7 40 88 3c 10 48 ff c2 48 39 d1 7f}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

