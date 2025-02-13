rule Backdoor_Win32_Spiderpig_A_2147777970_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Spiderpig.A"
        threat_id = "2147777970"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Spiderpig"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f 84 aa 01 00 00 80 39 4c 0f 85 30 01 00 00 80 79 01 43 0f 85 26 01 00 00 80 79 02 5f 0f 85 1c 01 00 00 8b f9}  //weight: 1, accuracy: High
        $x_1_2 = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTM" ascii //weight: 1
        $x_10_3 = {77 62 65 6d 00 00 00 00 5c 25 64 00 31 32 37 2e 30 2e 30 2e 31 [0-16] 2f [0-8] 2e 62 69 6e [0-16] 63 6f 6e 66 69 67 20 70 61 74 68 3a 25}  //weight: 10, accuracy: Low
        $x_10_4 = {55 6a 00 68 00 01 80 84 6a 00 6a 00 68 ?? ?? ?? 00 68 ?? ?? ?? 00 68 ?? ?? ?? 00 53 c7 44 24 3c 80 33 80 80 ff 15 ?? ?? ?? 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

