rule Trojan_Win64_BadJoke_KK_2147947322_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BadJoke.KK!MTB"
        threat_id = "2147947322"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BadJoke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_20_1 = {48 8b c1 83 e0 03 42 0f b6 04 30 30 04 0b 48 ff c1 8b 44 24 48 48 3b c8 72}  //weight: 20, accuracy: High
        $x_10_2 = {66 31 18 48 83 c0 02 48 3b c2 75 f4}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

