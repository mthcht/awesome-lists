rule Trojan_Win64_Miancha_CAF_2147846249_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Miancha.CAF!MTB"
        threat_id = "2147846249"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Miancha"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8d 0d 89 07 01 00 ff ?? ?? ?? ?? ?? 48 8b c8 48 8d 15 89 07 01 00 ff ?? ?? ?? ?? ?? 41 b9 0a 00 00 00 48 c7 44 24 20 00 00 00 00 4c 8d 84 24 c0 00 00 00 33 c9 48 8d ?? ?? ?? ?? ?? ff ?? 33 d2 48 8d 8c 24 c0 00 00 00 ff ?? ?? ?? ?? ?? 48 8b 8c 24 d0 01 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = "cmdshell" ascii //weight: 1
        $x_1_3 = "cmdshell_deinit" ascii //weight: 1
        $x_1_4 = "cmdshell_init" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

