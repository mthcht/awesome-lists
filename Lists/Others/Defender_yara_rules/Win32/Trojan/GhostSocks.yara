rule Trojan_Win32_GhostSocks_MKV_2147909376_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GhostSocks.MKV!MTB"
        threat_id = "2147909376"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GhostSocks"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 d8 0f b6 c0 33 54 85 ?? 8b 5c 24 18 88 14 3b 47 8b 54 24 24 8b 4c 24 28 0f b6 44 24 0f 0f b6 74 24 0e 39 f9 7f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GhostSocks_GZT_2147923548_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GhostSocks.GZT!MTB"
        threat_id = "2147923548"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GhostSocks"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {14 5f 45 31 46 e0 32 d7 68 ?? ?? ?? ?? a8 44 03 58 06}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

