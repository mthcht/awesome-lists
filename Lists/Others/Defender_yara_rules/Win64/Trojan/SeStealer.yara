rule Trojan_Win64_SeStealer_A_2147905353_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/SeStealer.A!MTB"
        threat_id = "2147905353"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "SeStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {41 8b 12 48 8b c5 49 03 d3 0f b6 0a 84 c9 ?? ?? 48 6b c0 ?? 48 0f be c9 48 8d 52 01 48 03 c1 0f b6 0a 84 c9 ?? ?? 48 3b c3 ?? ?? 41 ff c1 49 83 c2 ?? 45 3b c8}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

