rule Trojan_Win64_PIEEEEEEEEEE_ARAF_2147974839_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/PIEEEEEEEEEE.ARAF!MTB"
        threat_id = "2147974839"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "PIEEEEEEEEEE"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {55 8b ec 83 ec 0c 8b 45 08 89 45 fc 8b 4d fc 8b 55 08 03 51 3c 89 55 f8 6a 40 68 00 30 00 00 8b 45 f8 8b 48 50 51 6a 00 ff 15 2c 40 07}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

