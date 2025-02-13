rule Trojan_Win64_Trubot_ZF_2147847916_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Trubot.ZF!MTB"
        threat_id = "2147847916"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Trubot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f af c8 8b c1 33 d2 b9 05 00 00 00 f7 f1 8b c2 88 44 24 ?? 0f b6 44 24 ?? 0f b6 c8 8b 05 ?? ?? ?? ?? d3 e8 0f be 4c 24 ?? 0f b6 54 24 ?? 03 ca 2b 0d ?? ?? ?? ?? 33 c1 0f be 0d ?? ?? ?? ?? 2b c8 8b c1 88 05 ?? ?? ?? ?? 0f be 44 24 ?? 99 b9 05 00 00 00 f7 f9 8b 0d ?? ?? ?? ?? 03 c8 8b c1 88 44 24 ?? e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

