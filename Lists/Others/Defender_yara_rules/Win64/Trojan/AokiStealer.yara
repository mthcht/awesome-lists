rule Trojan_Win64_AokiStealer_BZ_2147981022_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AokiStealer.BZ!MTB"
        threat_id = "2147981022"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AokiStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 34 03 31 ce 4c 8d 04 9b 41 31 f0 44 88 04 18 48 ff c3 0f 1f 00 48 39 da 7f e4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

