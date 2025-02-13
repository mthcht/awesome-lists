rule Trojan_Win32_Xowiro_A_2147730105_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Xowiro.A"
        threat_id = "2147730105"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Xowiro"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a d8 80 e3 fc c0 e3 ?? 0a 5c 0f ?? 88 5d ?? 8a d8 24 ?? c0 e0 ?? 0a 04 0f c0 e3 ?? 0a 5c 0f ?? 88 04 16 8a 45 ?? 46 88 04 16 8b 45 ?? 46 88 1c 16 83 c1 ?? 46 3b 08 72}  //weight: 1, accuracy: Low
        $x_1_2 = {03 45 fc 89 01 c9 c3 a1 ?? ?? ?? ?? b9 ?? ?? ?? ?? e8 ?? ?? ?? ?? 0f b7 05 ?? ?? ?? ?? 25 ?? ?? 00 00 c3 e8 ?? ?? ?? ?? 30 02 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

