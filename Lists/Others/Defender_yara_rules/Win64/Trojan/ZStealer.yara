rule Trojan_Win64_ZStealer_AZ_2147982919_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ZStealer.AZ!MTB"
        threat_id = "2147982919"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ZStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_12_1 = {0f b6 02 48 8d 52 ?? 8b 4c 24 70 33 c8 69 c1 ?? ?? ?? ?? 89 44 24 70 49 83 e8}  //weight: 12, accuracy: Low
        $x_8_2 = {41 0f b7 10 4d 8d 40 ?? 6b c8 21 83 ca ?? 8b c2 33 c1 49 83 ea}  //weight: 8, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

