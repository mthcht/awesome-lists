rule Virus_Win32_Cutef_B_2147594930_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Cutef.B"
        threat_id = "2147594930"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Cutef"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 86 80 00 00 00 5e 03 c6 83 c0 0c 8b 18 81 3c 33 4b 45 52 4e 75 0c 81}  //weight: 1, accuracy: High
        $x_1_2 = {7c 33 04 45 4c 33 32 75 02 eb 05 83 c0 14 eb e4 83 e8 0c 83 c0 10 8b 00}  //weight: 1, accuracy: High
        $x_1_3 = {8b 04 30 25 00 f0 ff ff 8d 9d b6 14 40 00 53 64 67 ff 36 00 00 64 67 89}  //weight: 1, accuracy: High
        $x_1_4 = {26 00 00 66 81 38 4d 5a 74}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Virus_Win32_Cutef_C_2147594931_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Cutef.C"
        threat_id = "2147594931"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Cutef"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 5e 3c 03 f3 66 81 3e 50 45}  //weight: 1, accuracy: High
        $x_1_2 = {8b 46 0c 03 c1 81 38 4b 45 52 4e}  //weight: 1, accuracy: High
        $x_1_3 = {83 c6 3c 8b 36 03 75 ec 66 81 3e 50 45 0f 85}  //weight: 1, accuracy: High
        $x_1_4 = {89 45 4e 8b f8 66 81 3f 4d 5a 0f 85 1d 01 00 00 8b 7f 3c 03 f8 66 81 3f 50 45}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

