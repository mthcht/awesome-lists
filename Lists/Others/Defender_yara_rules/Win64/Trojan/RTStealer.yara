rule Trojan_Win64_RTStealer_A_2147851340_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/RTStealer.A!MTB"
        threat_id = "2147851340"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "RTStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f b6 14 0b 48 8d 49 ?? 80 f2 ?? 41 ff c0 88 51 ?? 48 8b 54 24 ?? 49 63 c0 48 3b c2 72}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

