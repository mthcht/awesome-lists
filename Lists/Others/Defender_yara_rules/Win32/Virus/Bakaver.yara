rule Virus_Win32_Bakaver_A_2147605540_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Bakaver.gen!A"
        threat_id = "2147605540"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Bakaver"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "27"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {e8 00 00 00 00 5d 81 ed 13 10 40 00 8d 85 2c 20 40 00 50 ff ?? ?? ?? ?? ?? 8b 58 3c 8b 5c 03 78 8b 4c 03 18 89 8d 9d 33 40 00 33 c9 8b 7c 03 20 8b 54 03 1c 03 d0 8b 5c 03 24 03 d8 8b 34 07 03 f0 57 8d bd 93 20 40 00 51 b9 0f 00 00 00 f3 a6 59 5f}  //weight: 10, accuracy: Low
        $x_10_2 = {50 8b f0 66 81 38 4d 5a 75 33 66 83 78 18 40 72 2c 0f b7 48 3c 03 c1 81 38 50 45 00 00 75 1e 66 81 78 04 4c 01 72 16 66 81 78 04 60 01 73 0e 66 83 78 5c 02 72 07 66 83 78 5c 03 76 05 e9 50 03 00 00 97 8b 87 80 00 00 00 e8 57 03 00 00 83 38 00 74 ea 92 8b 42 0c e8 49 03 00 00 81 38 4b 45 52 4e 75 09 81 78 04 45 4c 33 32}  //weight: 10, accuracy: High
        $x_10_3 = {f6 85 e1 33 40 00 01 74 23 b0 e9 aa 8b 85 bd 33 40 00 8b 40 0c 8b 8d ad 33 40 00 2b c1 8b cf 2b 8d e2 33 40 00 83 c1 04 2b c1 ab c3 b0 c3 aa c3}  //weight: 10, accuracy: High
        $x_5_4 = {03 41 56 50 04 53 43 41 4e 06 46 49 4e 44 56 49 02 46 2d 00 0d 41 4e 54 49 2d 56 49 52 2e 44 41 54 00 0b 43 48 4b 4c 49 53 54 2e 4d 53 00 08 41 56 50 2e 43 52 43 00 08 49 56 42 2e 4e 54 5a}  //weight: 5, accuracy: High
        $x_1_5 = {1f 23 00 00}  //weight: 1, accuracy: High
        $x_1_6 = "baka.wav" ascii //weight: 1
        $x_1_7 = "SfcIsFileProtected" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_1_*))) or
            ((3 of ($x_10_*))) or
            (all of ($x*))
        )
}

