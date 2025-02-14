rule Trojan_Win64_PoolInject_GA_2147933552_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/PoolInject.GA!MTB"
        threat_id = "2147933552"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "PoolInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {8b 4c 24 28 33 c8 8b c1 89 44 24 24 8b 44 24 2c 89 44 24 28 eb b9}  //weight: 3, accuracy: High
        $x_3_2 = {0f b6 c8 48 8b 44 24 38 48 d3 e8 48 25 ff 00 00 00 48 63 4c 24 24 48 8b 54 24 28 48 03 d1 48 8b ca 48 8b 54 24 30 88 04 0a}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

