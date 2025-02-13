rule Backdoor_Win32_Unskal_A_2147688510_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Unskal.A"
        threat_id = "2147688510"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Unskal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8a 03 3c 5e 0f 94 c2 74 08 3c 3d 0f 85 f5 00 00 00 8a 43 f0 89 d9 83 e8 34 3c 01 0f 87 e7 00 00 00 84 d2 89 d8 74 31 39 45 e4}  //weight: 5, accuracy: High
        $x_5_2 = {55 3c 19 89 e5 77 05 83 c0 41 eb 1e 3c 33 77 05 83 c0 47 eb 15 3c 3d 77 05 83 e8 04 eb 0c 3c 3e}  //weight: 5, accuracy: High
        $x_5_3 = {80 fa 19 76 17 89 fa 80 fa 20 74 10 80 fa 2f 74 0b 80 78 01 5e}  //weight: 5, accuracy: High
        $x_5_4 = {50 83 fb 22 0f 84 93 01 00 00 77 67 83 fb 11 77 29 83 fb 10 0f 83 70 03 00 00 83 fb 09 0f 84 e7 00 00 00 83 fb 0d 0f 84 c9 00 00 00 83 fb 08 0f 85 33 02 00 00}  //weight: 5, accuracy: High
        $x_1_5 = {26 6f 70 3d 25 64 26 69 64 3d 25 73 26 75 69 3d 25 73 26 77 76 3d 25 64 26 ?? ?? 3d 25 73}  //weight: 1, accuracy: Low
        $x_1_6 = "[%s] - [%.2d/%.2d/%d %.2d:%.2d:%.2d]" ascii //weight: 1
        $x_5_7 = {80 7d b4 55 0f 84 79 06 00 00 80 7d b4 69 75 19 e9 65 06 00 00 c6 45 b4 64 b1 6c e9 87 01 00 00 c6 45 b4 6f e9 5e 06 00 00 80 7d b4 70 7f 52 80 7d b4 6f 0f 8d f3 00 00 00 80 7d b4 63 74 74}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Unskal_B_2147689412_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Unskal.B"
        threat_id = "2147689412"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Unskal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {b0 20 2a c2 32 c3 42 88 04 0e 41 8a 19 84 db 75}  //weight: 1, accuracy: High
        $x_1_2 = "{88EB3725-F97E-4C37-9CE8-0A928A20320C}" ascii //weight: 1
        $x_1_3 = "\\winservs.exe" ascii //weight: 1
        $x_1_4 = "\\OracleJava\\javaw.exe" ascii //weight: 1
        $x_1_5 = {5c 6e 73 73 6b 72 6e 6c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Backdoor_Win32_Unskal_C_2147693061_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Unskal.C"
        threat_id = "2147693061"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Unskal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b f9 2b fa 8a 0a 84 c9 74 ?? 80 f1 2a 46 [0-2] 88 0c 17 [0-8] 42 [0-7] 3b ?? 72}  //weight: 1, accuracy: Low
        $x_5_2 = {53 8d 59 ff 03 de 8a 0b 8b c2 80 e9 30 25 01 00 00 80 79 05 48 83 c8 fe 40 74 0a 02 c9 80 f9 09 7e 03 80 c1 f7 0f be c9 03 f9 42 4b 3b d6 72 d6 8b 4d fc 5b 8b c7 6a 0a 99 5f f7 ff 85 d2 74 04}  //weight: 5, accuracy: High
        $x_5_3 = {83 f9 5e 75 02 eb 0b 8b 55 fc 83 c2 01 89 55 fc eb cc 8b 45 fc 83 c0 01 89 45 fc c7 45 e4 00 00 00 00 eb 09 8b 4d e4 83 c1 01 89 4d e4 83 7d e4 33 73 2b 8b 55 fc 0f b6 02 50 e8 bb fe ff ff 83 c4 04 85 c0 74 0b 8b 4d f4 83 c1 01 89 4d f4 eb 02 eb 0b 8b 55 fc 83 c2 01 89 55 fc eb c6 83 7d f4 07 72 06 83 7d f4 32}  //weight: 5, accuracy: High
        $x_5_4 = "oprat=2&uid=%I64u&uinfo=%s&win=%d.%d&vers=%s" ascii //weight: 5
        $x_5_5 = {5c 46 69 6e 64 53 74 72 [0-1] 5c 52 65 6c 65 61 73 65 5c 46 69 6e 64 53 74 72 2e 70 64 62 00}  //weight: 5, accuracy: Low
        $x_1_6 = {2f 76 69 65 77 74 6f 70 69 63 2e 70 68 70 00}  //weight: 1, accuracy: High
        $x_1_7 = "[PrintScreen]" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Unskal_D_2147694030_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Unskal.D"
        threat_id = "2147694030"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Unskal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "uinfo=%s&win=%d.%d&bits=%d" ascii //weight: 1
        $x_1_2 = {00 04 75 28 8b 45 fc 33 d2 b9 b0 04 00 00 f7 f1 85 d2 75 05 e8 ?? ?? ?? ?? 6a 64 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

