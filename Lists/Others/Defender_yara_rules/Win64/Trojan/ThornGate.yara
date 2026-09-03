rule Trojan_Win64_ThornGate_B_2147977481_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ThornGate.B!dha"
        threat_id = "2147977481"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ThornGate"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {7a c3 19 5f 42 e6 8b d0 13 bc b4 e7 b1 e6 b7 b4 e7 bd 29 8c 51 da 36 90 b2 68 fc 0d 83 47 ae 11}  //weight: 1, accuracy: High
        $x_1_2 = {41 32 c5 44 88 1d ?? ?? ?? ?? 44 32 2d ?? ?? ?? ?? 41 32 c7 44 30 2d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

