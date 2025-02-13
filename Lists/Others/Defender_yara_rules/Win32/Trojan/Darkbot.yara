rule Trojan_Win32_Darkbot_GJT_2147850231_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Darkbot.GJT!MTB"
        threat_id = "2147850231"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Darkbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {83 c1 01 0f be 15 ?? ?? ?? ?? 33 ca 89 8d ?? ?? ?? ?? 8b 85 ?? ?? ?? ?? 8a 8c 05 ?? ?? ?? ?? 88 8d ?? ?? ?? ?? 0f be 95 ?? ?? ?? ?? 8b 85 ?? ?? ?? ?? 8d 0c 42 8b 95 ?? ?? ?? ?? 88 8c 15}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

