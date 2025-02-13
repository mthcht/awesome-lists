rule Trojan_Win32_Ircbrute_B_2147651169_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ircbrute.B"
        threat_id = "2147651169"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ircbrute"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 44 24 0c 56 8d 0c 06 e8 ?? ?? ?? ?? 30 01 83 c4 04 46 3b f7 7c ?? 5f}  //weight: 1, accuracy: Low
        $x_1_2 = {83 7d 10 00 8b 4d 08 56 8b f1 74 12 8b 55 0c 8a 02 ff 4d 10 88 01 41 42 83 7d 10 00 75 f1 8b c6}  //weight: 1, accuracy: High
        $x_1_3 = {25 73 65 72 61 73 65 6d 65 5f 25 64 25 64 25 64 25 64 25 64 2e 65 78 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

