rule Trojan_Win64_ACRStealer_ETL_2147944753_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ACRStealer.ETL!MTB"
        threat_id = "2147944753"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ACRStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 89 44 24 20 48 c7 40 10 12 00 00 00 48 8d 0d f8 a0 01 00 48 89 48 08 48 8b 4c 24 38 48 89 4c 24 30 48 8d 05 40 8d 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

