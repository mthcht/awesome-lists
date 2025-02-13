rule Trojan_Win32_Gularger_F_2147749583_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gularger.F!dha"
        threat_id = "2147749583"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gularger"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {83 c4 08 0f b6 45 ff 83 c0 01 99 f7 7d 0c 88 55 ff eb 8f 8b e5 5d c3}  //weight: 2, accuracy: High
        $x_2_2 = {6a 02 8b 45 08 50 8d 4d fc 51 e8 ?? ?? ?? ?? 83 c4 0c 6a 02 8b 55 08 83 c2 02 52 8d 85 d4 f6 ff ff 50 e8 ?? ?? ?? ?? 83 c4 0c 81 7d fc 00 08 00 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

