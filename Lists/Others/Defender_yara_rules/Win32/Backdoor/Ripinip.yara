rule Backdoor_Win32_Ripinip_2147605803_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Ripinip"
        threat_id = "2147605803"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Ripinip"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {49 70 72 69 70 00 00 00 2e 69 6e 66 00 00 00 00 6c 62 6b 00 5c 69 6e 66 5c 69 70 00 2e 64 61 74 00 00 00 00 6c 69 70 00 6c 65 64 5c 00 00 00 00 63 79 63 00 63 3a 5c 72 65 00 00 00 5c 6e 69 70 72 70 00 00 2e 64 6c 6c 00 00 00 00 73 68 00 00 5c 70 77 66}  //weight: 2, accuracy: High
        $x_1_2 = "%SystemRoot%\\System32\\svchost.exe -k netsvcs" ascii //weight: 1
        $x_1_3 = "Remote IPRIP Service" ascii //weight: 1
        $x_2_4 = {5c 66 73 00 72 65 70 00 2e 65 78 65 00 00 00 00 70 77 66 [0-1] 73 68 [0-2] 2e 64 6c 6c [0-4] 43 6f 6e 74 72 6f 6c 53 65 74 5c 53 65 72 76 00 69 63 65 73 5c 49 70 00 72 69 70 5c 00 00 00 00 5c 6e 69 70 [0-4] 72 70 2e 64 6c 6c}  //weight: 2, accuracy: Low
        $x_2_5 = {53 65 72 76 69 63 65 44 6c 6c 00 00 50 61 72 61 6d 65 74 65 72 73 5c 00 53 74 61 72 74 00 00 00 72 69 70 5c 00 00 00 00 69 63 65 73 5c 49 70 00 43 6f 6e 74 72 6f 6c 53 65 74 5c 53 65 72 76 00 5c 6e 69 70 72 70 2e 64 6c 6c 00 00 48 4b 45 59 5f 4c 4f 43 41 4c 5f 4d 41 43 48 49 4e 45 5c 53 59 53 54 45 4d 5c 43 75 72 72 65 6e 74 00 00 00 5c 2a 2e 2a}  //weight: 2, accuracy: High
        $x_2_6 = {48 4b 45 59 5f 4c 4f 43 41 4c 5f 4d 41 43 48 49 4e 45 5c 53 4f 46 54 57 41 52 45 5c 43 6c 61 73 73 65 73 5c 43 4c 53 49 44 5c 7b 44 43 38 38 38 36 33 31 2d 35 37 46 35 2d 34 41 46 34 2d 38 36 42 33 2d 42 44 45 35 46 38 35 34 44 43 42 46 7d 5c 00 00 00 48 4b 45 59 5f 4c 4f 43 41 4c 5f 4d 41 43 48 49 4e 45 5c 53 4f 46 54 57 41 52 45 5c 43 6c 61 73 73 65 73 5c 50 57 46 6c 61 73 68 2e 50 6f 77 65 72 46 6c 61 73 68 5c}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Ripinip_2147605804_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Ripinip"
        threat_id = "2147605804"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Ripinip"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {48 4b 45 59 5f 4c 4f 43 41 4c 5f 4d 41 43 48 49 4e 45 5c 53 4f 46 54 57 41 52 45 5c 43 6c 61 73 73 65 73 5c 43 4c 53 49 44 5c 7b 44 43 38 38 38 36 33 31 2d 35 37 46 35 2d 34 41 46 34 2d 38 36 42 33 2d 42 44 45 35 46 38 35 34 44 43 42 46 7d 5c 00 5c 53 4f 46 54 57 61 [0-64] 74 2e 6b 6b 77 79 78 2e 63 6f 6d 2f 75 78 62 2f 62 6d 77}  //weight: 2, accuracy: Low
        $x_2_2 = {78 70 6c 6f 72 65 2e 65 78 65 00 30 00 00 00 31 00 00 00 68 74 74 70 3a 2f 2f 63 74 2e 6b 6b 77 79 78 2e 63 6f 6d 2f 75 78 62 2f 62 6d 77 63 74 2e 72 61 72}  //weight: 2, accuracy: High
        $x_2_3 = {65 78 65 63 75 74 65 3d 00 00 00 00 73 68 65 6c 6c 00 00 00 6f 52 75 6e 5d 0d 0a 00 5b 41 75 74 00 00 00 00 2e 65 78 65 00 00 00 00 75 64 6b 00 64 3a 5c 72 65 00 00 00 6f 70 65 6e 3d 00 00 00 52 75 6e 2e 69 6e 66 00 41 75 74 6f}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Ripinip_C_2147608027_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Ripinip.C"
        threat_id = "2147608027"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Ripinip"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "ChangeServiceConfig2A" ascii //weight: 10
        $x_10_2 = "%SystemRoot%\\System32\\svchost.exe -k netsvcs" ascii //weight: 10
        $x_1_3 = "Remote IPRIP Service" ascii //weight: 1
        $x_1_4 = "\\\\.\\PhysicalDrive%d" ascii //weight: 1
        $x_1_5 = {6c 65 64 5c 00 00 00 00 63 79 63 00 63 3a 5c 72 65 00 00 00 5c 6e 69 70 72 70 2e 64 6c 6c 00 00}  //weight: 1, accuracy: High
        $x_1_6 = {53 65 72 76 69 63 65 44 6c 6c 00 00 50 61 72 61 6d 65 74 65 72 73 5c 00 53 74 61 72 74 00 00 00 72 69 70 5c 00 00 00 00 69 63 65 73 5c 49 70 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Ripinip_H_2147617631_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Ripinip.H"
        threat_id = "2147617631"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Ripinip"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 84 24 04 05 00 00 41 3a 5c 00 ff 15}  //weight: 1, accuracy: High
        $x_1_2 = {81 7e 04 01 14 00 00 75 1e 8b 56 08 6a 00 8d 46 0c 50 52 55 57 ff 15 ?? ?? ?? ?? 56 8b cb e8 ?? ?? ff ff 85 c0 75 d9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Ripinip_L_2147627972_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Ripinip.L"
        threat_id = "2147627972"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Ripinip"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "C:\\boot.bin" ascii //weight: 5
        $x_5_2 = {2e 64 6c 6c 00 49 6e 73 74 61 6c 6c 00 52 75 6e 49 6e 73 74 61 6c 6c 41}  //weight: 5, accuracy: High
        $x_3_3 = {53 68 c8 24 22 00 56 ff 15}  //weight: 3, accuracy: High
        $x_1_4 = "systemp.log" ascii //weight: 1
        $x_1_5 = "sysout.log" ascii //weight: 1
        $x_1_6 = "KeServiceDescriptorTable" ascii //weight: 1
        $x_1_7 = "\\svchost.exe -k netsvcs" wide //weight: 1
        $x_1_8 = "Neo,welcome to the desert of real." wide //weight: 1
        $x_1_9 = "welcome to this word" wide //weight: 1
        $x_1_10 = "<%s*%d*%d*%d*%d*>" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_3_*) and 5 of ($x_1_*))) or
            ((2 of ($x_5_*) and 3 of ($x_1_*))) or
            ((2 of ($x_5_*) and 1 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Ripinip_O_2147646262_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Ripinip.O"
        threat_id = "2147646262"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Ripinip"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {49 73 68 65 6c 6c 2e 64 6c 6c 00 49 6e 73 74 61 6c 6c 00 52 75 6e 49 6e 73 74 61 6c 6c}  //weight: 1, accuracy: High
        $x_1_2 = {8b f8 83 c4 14 85 ff 74 1b 6a 02 68 ?? ff ff ff 57 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

