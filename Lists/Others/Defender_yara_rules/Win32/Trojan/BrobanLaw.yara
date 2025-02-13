rule Trojan_Win32_BrobanLaw_A_2147692532_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BrobanLaw.A"
        threat_id = "2147692532"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BrobanLaw"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "lvepaeanjfbsms" wide //weight: 1
        $x_1_2 = {b8 01 02 00 00 e8 b0 94 e8 ff 05 ce 77 00 00 50 e8 f5 1c e9 ff e8 a8 64 ff ff 33 c0 5a 59 59 64 89 10 68 55 b2 57 00 c3 e9 4d ac e8 ff eb f8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BrobanLaw_A_2147692532_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BrobanLaw.A"
        threat_id = "2147692532"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BrobanLaw"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {64 ff 35 00 00 00 00 64 89 25 00 00 00 00 58 c3 e9 05 00 68}  //weight: 1, accuracy: Low
        $x_1_2 = {8b f9 8b f2 4e 85 f6 7c (15|16) 46 33 d2 8b e8 03 ea [0-4] 8b df 2a cb 88 4d 00 42 4e 75 (ed|ee)}  //weight: 1, accuracy: Low
        $x_1_3 = {ba c4 06 00 00 e8 ?? ?? ?? ?? b8 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? ba 3c 00 00 00 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

