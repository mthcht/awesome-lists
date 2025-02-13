rule Trojan_Win64_DriverInject_KG_2147900617_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DriverInject.KG!MTB"
        threat_id = "2147900617"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DriverInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 89 45 37 48 8b 0f e8 6a 01 00 00 ff c3 48 8d 7f 08 83 fb 17 72 ed 48 8b 4d 47 48 33 cc e8 5f 54 00 00 4c 8d 9c 24 f0 00 00 00 49 8b 5b 10 49 8b 7b}  //weight: 1, accuracy: High
        $x_1_2 = {0f be 0e 8b c3 48 33 c8 48 ff c6 0f b6 d1 48 8d 0d fc 47 00 00 c1 e8 08 8b 1c 91 33 d8 83 c7 ff 75 de}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

