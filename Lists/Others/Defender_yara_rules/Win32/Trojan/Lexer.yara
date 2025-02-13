rule Trojan_Win32_Lexer_A_2147687074_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lexer.A"
        threat_id = "2147687074"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lexer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {42 33 ff b8 ?? ?? ?? ?? 8b 0d 70 76 40 00 8a 0c 39 80 e9 4d 88 08 8a 08 88 0d ?? ?? ?? ?? 8a 0d ?? ?? ?? ?? 80 f1 0b 88 08 47 40 4a 75}  //weight: 1, accuracy: Low
        $x_1_2 = {68 03 01 00 00 e8 ?? ?? ?? ?? 8d 45 ec ba ?? ?? ?? ?? b9 04 01 00 00 e8 ?? ?? ?? ?? 8d 45 ec ba ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 55 ec}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

