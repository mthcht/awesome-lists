rule Backdoor_Win32_Nuwar_A_2147790242_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Nuwar.A"
        threat_id = "2147790242"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Nuwar"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {e3 32 49 8b 34 8b 03 f5 33 ff fc 33 c0 ac 3a c4 74 07 c1 cf 0d 03 f8 eb f2}  //weight: 2, accuracy: High
        $x_2_2 = {77 07 0f be c0 83 e8 30 c3 56 33 f6 3c 41 7c 04 3c 46 7e 15}  //weight: 2, accuracy: High
        $x_3_3 = {2e 69 6e 69 00 00 [0-2] 5b 62 6c 61 63 6b 6c 69 73 74 5d}  //weight: 3, accuracy: Low
        $x_1_4 = "[peers]" ascii //weight: 1
        $x_1_5 = "Counter=0" ascii //weight: 1
        $x_1_6 = "[counter]" ascii //weight: 1
        $x_1_7 = "Win%s %d.%d" ascii //weight: 1
        $x_1_8 = "TCP connection is failed" ascii //weight: 1
        $x_2_9 = {6e 6f 72 65 70 6c 79 00 40 61 76 70 2e 00}  //weight: 2, accuracy: High
        $x_2_10 = "Windoss NT" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            ((1 of ($x_3_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Nuwar_C_2147792375_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Nuwar.C"
        threat_id = "2147792375"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Nuwar"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5b 70 65 65 72 73 5d 00}  //weight: 1, accuracy: High
        $x_1_2 = {5b 6c 6f 63 61 6c 5d 00}  //weight: 1, accuracy: High
        $x_1_3 = {5b 63 6f 6e 66 69 67 5d 00}  //weight: 1, accuracy: High
        $x_1_4 = "ControlService" ascii //weight: 1
        $x_1_5 = "WritePrivateProfileString" ascii //weight: 1
        $x_1_6 = {81 7d f8 00 00 00 01 0f 85 ?? 01 00 00 f6 45 f4 cc 74 ?? 8b 4d e4 66 81 39 4d 5a 0f 85 ?? 01 00 00 8b 41 3c 03 c1 81 38 50 45 00 00 0f 85 ?? 01 00 00 66 81 78 18 0b 01 0f 85 ?? 01 00 00 2b d9 66 83 78 06 00 0f b7 48 14 8d 4c 01 18 0f 86 ?? 01 00 00 8b 41 0c 3b d8 72 ?? 8b 51 08 03 d0 3b da 73 ?? f6 41 27 80}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Nuwar_A_2147792379_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Nuwar.gen!A"
        threat_id = "2147792379"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Nuwar"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 45 f4 50 8d b3 ?? ?? ?? 00 ff 36 e8 ?? ?? 00 00 59 50 ff 36 ff 75 f8 ff d7 6a 00 8d 45 f4 50 6a 02 8d 45 fc 50 ff 75 f8 c6 45 fc 0d c6 45 fd 0a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Nuwar_D_2147792404_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Nuwar.D"
        threat_id = "2147792404"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Nuwar"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {5c 00 44 00 6f 00 73 00 44 00 65 00 76 00 69 00 63 00 65 00 73 00 5c 00 6d 00 73 00 54 00 43 00 50 00 55 00 44 00 50 00 00 00 00 00 5c 00 44 00 65 00 76 00 69 00 63 00 65 00 5c 00 6d 00 73 00 54 00 43 00 50 00 55 00 44 00 50 00}  //weight: 10, accuracy: High
        $x_10_2 = "projects\\rootkit\\Debug\\i386\\msTCPUDP.pdb" ascii //weight: 10
        $x_3_3 = "ZwQuerySystemInformation failed! ulNeededSize = %ul, NtStatus = %u." ascii //weight: 3
        $x_1_4 = {6b 00 6c 00 69 00 66 00 2e 00 73 00 79 00 73 00 00 00 00 00 61 00 76 00 70 00 2e 00 65 00 78 00 65 00 00 00 77 00 61 00 74 00 63 00 68 00 64 00 6f 00 67 00 2e 00 73 00 79 00 73 00 00 00 00 00 77 00 73 00 63 00 6e 00 74 00 66 00 79 00 2e 00 65 00 78 00 65 00 00 00 76 00 73 00 64 00 61 00 74 00 61 00 6e 00 74 00 2e 00 73 00 79 00 73 00 00 00 00 00 7a 00 63 00 6c 00 69 00 65 00 6e 00 74 00 2e 00 65 00 78 00 65 00 00 00 62 00 63 00 66 00 69 00 6c 00 74 00 65 00 72 00 2e 00 73 00 79 00 73 00}  //weight: 1, accuracy: High
        $x_1_5 = {67 00 63 00 61 00 73 00 73 00 65 00 72 00 76 00 2e 00 65 00 78 00 65 00 00 00 00 00 69 00 63 00 6d 00 6f 00 6e 00 2e 00 65 00 78 00 65 00 00 00 69 00 6e 00 65 00 74 00 75 00 70 00 64 00 2e 00 65 00 78 00 65 00 00 00 6e 00 6f 00 64 00 33 00 32 00 6b 00 72 00 6e 00 2e 00 65 00 78 00 65 00 00 00 00 00 6e 00 6f 00 64 00 33 00 32 00 72 00 61 00 2e 00 65 00 78 00 65 00 00 00 70 00 61 00 76 00 66 00 6e 00 73 00 76 00 72 00 2e 00 65 00 78 00 65 00 00 00 00 00 61 00 76 00 67 00 2e 00 65 00 78 00 65 00 00 00 61 00 76 00 67 00 73 00 63 00 61 00 6e 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

