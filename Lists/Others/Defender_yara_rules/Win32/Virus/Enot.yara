rule Virus_Win32_Enot_A_2147599883_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Enot.A"
        threat_id = "2147599883"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Enot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {9c 51 8b 5d 08 b9 a6 18 00 00 8d b3 ?? ?? ?? ?? 81 3e eb 02 41 44 75 08 83 c6 0f 83 e9 0f e2 f0 8a 06 34 42 88 06 46 e2 e7 59 9d}  //weight: 1, accuracy: Low
        $x_1_2 = {56 57 53 55 9c 8b 7d 08 03 7f 3c 83 c7 04 83 c7 14 81 7f 34 1e f1 ad 0b 75 0e b8 01 00 00 00 9d 5d 5b 5f 5e}  //weight: 1, accuracy: High
        $x_1_3 = {50 8b 7d e4 b9 28 00 00 00 b0 00 f3 aa 8b 7d e4 c7 07 2e 74 6c 73 8b 75 f4 8b 46 24 89 47 08 8f 47 0c 57 8b f0 56 8b 75 f4 8b 46 24}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

