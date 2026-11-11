rule Trojan_Win64_RidgeBot_BA_2147981838_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/RidgeBot.BA!MTB"
        threat_id = "2147981838"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "RidgeBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b c2 ff c0 8b 4c 24 24 33 c8 8b c1 48 63 4c 24 20 48 8b 54 24 28 88 04 0a 48 63 44 24 20 48 8b 4c 24 28 0f b6 04 01 33 44 24 60 48 63 4c 24 20 48 8b 54 24 28 88 04 0a eb}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

