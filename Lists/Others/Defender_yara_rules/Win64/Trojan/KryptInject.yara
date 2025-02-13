rule Trojan_Win64_KryptInject_RB_2147748679_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/KryptInject.RB!MSR"
        threat_id = "2147748679"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "KryptInject"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {0f b7 02 8b c8 c1 e8 0c 81 e1 ff 0f 00 00 83 f8 03 74 0b 83 f8 0a 75 0a 4a 01 1c 09 eb 04 42 01 1c 09 45 8b 53 04 41 ff c0 48 83 c2 02 41 8b c0 49 8d 4a f8 48 d1 e9 48 3b c1 72 c4}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

