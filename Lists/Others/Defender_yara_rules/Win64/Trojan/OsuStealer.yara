rule Trojan_Win64_OsuStealer_AOS_2147975140_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/OsuStealer.AOS!MTB"
        threat_id = "2147975140"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "OsuStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 8b c8 48 c1 e9 08 80 f1 26 88 4d 31 48 8b c8 48 c1 e8 10 34 74 48 c1 e9 0c 88 45 33 80 f1 eb 48 8b c2 88 4d 32 48 c1 e8 14 34 8e 88 45 34 48 8b c2 48 c1 e8 18}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

