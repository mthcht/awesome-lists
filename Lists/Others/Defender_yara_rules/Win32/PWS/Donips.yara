rule PWS_Win32_Donips_A_2147611501_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Donips.gen!A"
        threat_id = "2147611501"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Donips"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {be 52 41 57 00 8b c1 40 39 30 75 fb 8b f0 4a 75 f4 40 66 81 38 55 8b 75 f8 83 e8 05}  //weight: 3, accuracy: High
        $x_3_2 = {eb c3 68 24 01 00 00 ff 75 f8 68 dc a0 6c 6c ff 35 ?? ?? 00 10 e8 ?? ?? ff ff 59 59 ff d0 89 45 fc}  //weight: 3, accuracy: Low
        $x_2_3 = {7d 21 8b 55 08 03 55 fc 0f be 02 8b 0d ?? ?? ?? ?? c1 f9 08 0f be d1 33 c2 8b 4d 08 03 4d fc 88 01 eb c7}  //weight: 2, accuracy: Low
        $x_1_4 = {59 59 6a 00 68 45 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 6a 00 6a 04 6a 02 6a 00 6a 00 68 00 00 00 c0}  //weight: 1, accuracy: Low
        $x_1_5 = {5b 57 4d 49 44 5d 00 00 5b 57 4d 50 53 5d}  //weight: 1, accuracy: High
        $x_1_6 = {6d 70 72 61 70 69 2e 64 6c 6c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*))) or
            (all of ($x*))
        )
}

