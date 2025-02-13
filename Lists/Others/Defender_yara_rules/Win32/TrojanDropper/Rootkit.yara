rule TrojanDropper_Win32_Rootkit_AFH_2147606393_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Rootkit.AFH"
        threat_id = "2147606393"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Rootkit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 7c 24 18 02 75 62 b8 cd cc cc cc f7 64 24 2c c1 ea 03 81 fa e8 03 00 00 73 07 ba e8 03 00 00 eb 0d}  //weight: 1, accuracy: High
        $x_1_2 = {68 80 00 00 00 6a 02 6a 00 6a 01 68 00 00 00 40 51 ff 15 ?? ?? 00 10 8d 54 24 0c 6a 00 52 8b f0 68 00 1a 00 00 68 ?? ?? 00 10 56 c7 44 24 20 00 00 00 00 ff 15 ?? ?? 00 10}  //weight: 1, accuracy: Low
        $x_1_3 = "beep.sys" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanDropper_Win32_Rootkit_AFH_2147606393_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Rootkit.AFH"
        threat_id = "2147606393"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Rootkit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Cookie: ASPSESSIONIDACQADRDT=AMCJBFJAKJAPMNIKCDENGIIB" ascii //weight: 1
        $x_1_2 = "software\\microsoft\\windows\\currentversion\\explorer\\desktop" ascii //weight: 1
        $x_1_3 = "\"GNGOGLVANKGLV" ascii //weight: 1
        $x_1_4 = "mkgo$oro" ascii //weight: 1
        $x_1_5 = {50 4f 53 54 20 25 73 20 48 54 54 50 2f 31 2e 31 0d 0a 41 63 63 65 70 74 3a 20 2a 2f 2a 0d 0a 41 63 63 65 70 74 2d 4c 61 6e 67 75 61 67 65 3a 20 7a 68 2d 63 6e}  //weight: 1, accuracy: High
        $x_1_6 = "CreateToolhelp32Snapshot" ascii //weight: 1
        $x_1_7 = "CreateRemoteThread" ascii //weight: 1
        $x_1_8 = "WriteProcessMemory" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Rootkit_AFH_2147606393_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Rootkit.AFH"
        threat_id = "2147606393"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Rootkit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {73 6f 66 74 77 61 72 65 5c 6d 69 63 72 6f 73 6f 66 74 5c 77 69 6e 64 6f 77 73 5c 63 75 72 72 65 6e 74 76 65 72 73 69 6f 6e 5c 65 78 70 6c 6f 72 65 72 5c 64 65 73 6b 74 6f 70 00 00 73 79 73 66 69 6c 65}  //weight: 1, accuracy: High
        $x_1_2 = {5c 49 6e 50 72 6f 63 53 65 72 76 65 72 33 32 00 43 4c 53 49 44 5c 00 00 7b 45 32 35 43 32 39 41 42 2d 31 32 42 39 2d 34 35 32 33 2d 41 35 33 43 2d 33 32 34 42 35 46 42 41 36 34 38 43 7d}  //weight: 1, accuracy: High
        $x_1_3 = {4d 49 43 52 4f 53 4f 46 54 5c 57 49 4e 44 4f 57 53 5c 63 75 72 72 65 6e 74 76 65 72 73 69 6f 6e 5c 65 78 70 6c 6f 72 65 72 5c 53 48 45 4c 4c 45 58 45 43 55 54 45 48 4f 4f 4b 53 00 73 6f 66 74 77 61 72 65 5c}  //weight: 1, accuracy: High
        $x_1_4 = {22 25 73 5c 52 75 6e 64 6c 6c 33 32 2e 65 78 65 22 20 22 25 73 5c 73 68 65 6c 6c 33 32 2e 64 6c 6c 22 2c 43 6f 6e 74 72 6f 6c 5f 52 75 6e 44 4c 4c 20 22 25 73 22 00 00 46 33 00 00 53 68 65 6c 6c}  //weight: 1, accuracy: High
        $x_1_5 = {57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 00 00 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 00 6d 72 75 6c 69 73 74 00 25 58}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

