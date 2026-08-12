rule Trojan_Win64_CollectionStealer_LR_2147976005_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CollectionStealer.LR!MTB"
        threat_id = "2147976005"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CollectionStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {80 b4 04 f0 00 00 00 55 48 ff c0 48 83 f8 0d 72 ?? 48 89 9c 24 30 01 00 00 48 8d 8c 24 f0 00 00 00 48 89 b4 24 38 01 00 00 48 89 bc 24 40 01 00 00}  //weight: 20, accuracy: Low
        $x_10_2 = {0f b6 84 0c 00 01 00 00 48 ff c1 30 03 48 ff c3 48 83 ee 01 0f ?? ?? ?? ?? ?? 4c 8d 4c 24 20 ba 14 33 17 00 41 b8 20 00 00 00 48 8b cd}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

