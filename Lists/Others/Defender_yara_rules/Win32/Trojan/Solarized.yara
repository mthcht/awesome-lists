rule Trojan_Win32_Solarized_A_2147711952_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Solarized.A!dynapi"
        threat_id = "2147711952"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Solarized"
        severity = "Critical"
        info = "dynapi: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0d f1 28 0b 04 46 e3 6b 0e 46 ?? ?? 13 eb 00 09 ?? ?? d9 f8 74 30 00 2b ?? ?? d9 f8 78 30 00 2b}  //weight: 1, accuracy: Low
        $x_1_2 = {b9 68 40 23 4f f4 40 52 00 20 a8 47 23 68 05 46}  //weight: 1, accuracy: High
        $x_1_3 = {eb 6b 17 f1 08 01 17 f1 10 00 2b 44 9b 6a 2b 44 bb 60}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

