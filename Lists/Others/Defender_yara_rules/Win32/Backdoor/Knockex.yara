rule Backdoor_Win32_Knockex_C_2147598254_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Knockex.C"
        threat_id = "2147598254"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Knockex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 63 00 00 00 8b 7d f0 f2 ae 83 f9 00 0f 84 ?? ?? 00 00 81 3f 6f 6d 6d 61 75 ed 66 81 7f 04 6e 64 75 e5 80 7f 06 7c}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 7d 08 8b f7 b3 ?? ac 32 c3 aa fe c3 84 c0 75 f6 61 c9 c2 04 00 55 8b ec 60 8b 7d 08 8b f7 b3 ?? 66 ad 32 c3 66 ab fe c3 84 c0}  //weight: 1, accuracy: Low
        $x_1_3 = {ff 75 08 5f 57 5e b3 ?? ac 32 c3 aa fe c3 84 c0 75 f6 61 c9 c2 04 00 55 8b ec 60 ff 75 08 5f 8b f7 b3 ?? 66 ad 32 c3 66 ab fe c3 84 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Backdoor_Win32_Knockex_F_2147609519_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Knockex.F"
        threat_id = "2147609519"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Knockex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 8b ec 60 ff 75 08 5f 8d 37 c0 cb 05 80 cf 5a 80 cf 02 80 c3 90 f7 db c0 eb 0a fe c7 ff 75 0c 5b ac 32 c3 aa fe c3 84 c0 75 f6 61 c9 c2 08 00}  //weight: 1, accuracy: High
        $x_1_2 = {b2 8b 8b 70 6e 71 77 24 43 6f 75 6d 7e 6b 67 60 2d 5e 7d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Knockex_G_2147609521_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Knockex.G"
        threat_id = "2147609521"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Knockex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 8b ec 60 ff 75 08 5f 57 5e c1 c3 16 f7 d3 c0 eb 13 8b 5d 0c ac 32 c3 aa fe c3 84 c0 75 f6 61 c9 c2 08 00}  //weight: 1, accuracy: High
        $x_1_2 = "NbllcuW{aqbw{t" ascii //weight: 1
        $x_1_3 = {f9 c2 cc c9 d5 c8 c8 9d f8 d6 b2 a4 b5 a2 a8 a9 e6 97 ba a6 ca}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Knockex_H_2147614390_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Knockex.H"
        threat_id = "2147614390"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Knockex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e [0-2] 57 4d 44 4d 20 50 4d 53 50 20 53 65 72 76 69 63 65 [0-2] 5c 73 79 73 74 65 6d 33 32 5c 63 73 73 72 73 73 2e 65 78 65}  //weight: 2, accuracy: Low
        $x_2_2 = {45 6e 61 62 6c 65 46 69 72 65 77 61 6c 6c [0-2] 4f 75 74 70 6f 73 74 20 46 69 72 65 77 61 6c 6c 20 50 72 6f}  //weight: 2, accuracy: Low
        $x_2_3 = ":*:Enabled:DHCP Client" ascii //weight: 2
        $x_2_4 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 00 73 64 61 73 64 61 64 73 61 64 2e 65 78 65 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

