rule TrojanDropper_Win32_Pozz_A_2147631510_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Pozz.A"
        threat_id = "2147631510"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Pozz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 75 8b 00 00 e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 5a 8d 94 02 87 e6 0b 00}  //weight: 1, accuracy: Low
        $x_1_2 = {b9 8b 39 5b 00 b8 ?? ?? 54 00 81 c7 80 00 00 00 f3 ab 8b 8a 98 a4 c7 00}  //weight: 1, accuracy: Low
        $x_1_3 = {50 50 6a 03 50 50 68 c9 cb 08 c0 81 2c 24 c9 cb 08 00 68 ?? ?? ?? ?? e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

