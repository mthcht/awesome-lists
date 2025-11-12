rule Trojan_Win64_Anomalous_GVA_2147957275_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Anomalous.GVA!MTB"
        threat_id = "2147957275"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Anomalous"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {03 d9 85 c0 78 0c 8a 0c 03 48 88 0c 37 47 3b fa 72 f0 8b 9d 7c ff ff ff ff 45 d4 e9 41 ff ff ff}  //weight: 2, accuracy: High
        $x_1_2 = {8b 4d 84 89 01 8b 55 d4 3b 55 c0 0f 83 93 00 00 00 8b 45 8c 8b ca 0f af 4d 98 8d 04 40 03 c8 83 7d 8c 00 75 4d}  //weight: 1, accuracy: High
        $x_1_3 = {8b ca 56 8b 37 83 e1 1f 8b 7f 04 33 f2 33 fa d3 ce d3 cf 85 f6 0f 84}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

