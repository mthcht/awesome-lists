rule Trojan_Win64_WingoObfus_AB_2147901072_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/WingoObfus.AB!MTB"
        threat_id = "2147901072"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "WingoObfus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4c 8d 05 94 ed 06 00 46 0f b6 04 00 44 31 c2 88 14 1e 48 ff c3 48 89 f0 48 89 fa 48 39 d9 7e 34 48 89 c6 48 b8 25 ?? ?? ?? ?? ?? ?? ?? 48 89 d7 48 f7 eb 48 d1 fa 4c 8d 04 52 4a 8d 14 42 48 89 d8 48 29 d0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

