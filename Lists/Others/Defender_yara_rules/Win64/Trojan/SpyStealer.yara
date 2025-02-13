rule Trojan_Win64_SpyStealer_SA_2147902117_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/SpyStealer.SA!MTB"
        threat_id = "2147902117"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "SpyStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b 44 24 ?? 0f be 00 85 c0 74 2b 48 8b 44 24 ?? 0f b6 00 8b 0c 24 33 c8 8b c1 89 04 24 48 8b 44 24 ?? 48 ff c0 48 89 44 24 ?? 69 04 24 ?? ?? ?? ?? 89 04 24 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

