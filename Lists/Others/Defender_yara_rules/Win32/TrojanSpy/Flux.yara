rule TrojanSpy_Win32_Flux_AD_2147609563_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Flux.AD"
        threat_id = "2147609563"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Flux"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1502"
        strings_accuracy = "Low"
    strings:
        $x_1000_1 = {83 65 e8 00 8d 45 bc 50 ff 15 34 10 40 00 e8 5d 00 00 00 68 8c 10 40 00 68 88 10 40 00 e8 34 00 00 00 f6 45 e8 01 59 59 74 06 0f b7 45 ec eb 03}  //weight: 1000, accuracy: High
        $x_1000_2 = {fe 40 01 53 55 56 57 50 be f3 53 40 00 2b c0 8b fa 68 b8 53 40 00 64 ff 30 64 89 20 6a 0d 59 f3 ab 8b fa 64 8b 48 30 8c da f6 c2 04 75 74 ba}  //weight: 1000, accuracy: High
        $x_500_3 = {b0 10 84 45 1c 74 04 08 44 24 10 ff 73 2c ff 53 10 ff 73 30 ff 53 10 ff 53 24 50 ff 73 30 ff 53 18 ff 73 2c ff 53 18 58 59 85 c0 74 3f e3 10 6a 45 5a 80 7b 02 5a 75 03 83 c2 08 80 0c 02 08 33 43 04 8b 4d 20 50 ff 75 fc 68 ff 03 1f 00 e3 02}  //weight: 500, accuracy: High
        $x_1_4 = {52 74 6c 4e 74 53 74 61 74 75 73 54 6f 44 6f 73 45 72 72 6f 72 00 4e 74 41 6c 6c 6f 63 61 74 65 56 69 72 74 75 61 6c 4d 65 6d 6f 72 79 00 4e 74 46 72 65 65 56 69 72 74 75 61 6c 4d 65 6d 6f 72 79 00 4e 74 4f 70 65 6e 54 68 72 65 61 64 00 52 65 61 64 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 00 53 65 74 54 68 72 65 61 64 41 66 66 69 6e 69 74 79 4d 61 73 6b 00}  //weight: 1, accuracy: High
        $x_1_5 = {6b 65 72 6e 65 6c 33 32 2e 64 6c 6c [0-112] 5c 45 78 70 4c 6f 72 65 72 2e 65 58 65 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_1000_*) and 1 of ($x_500_*) and 2 of ($x_1_*))) or
            ((2 of ($x_1000_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Flux_C_2147609564_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Flux.C"
        threat_id = "2147609564"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Flux"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "50"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {88 16 0f be 09 8b 75 08 03 ca 23 c8 8a 8c ?? ?? ?? ?? ?? 03 f3 30 0e 43 3b}  //weight: 10, accuracy: Low
        $x_10_2 = "\\ExpLorer.eXe" ascii //weight: 10
        $x_10_3 = "NtOpenThread" ascii //weight: 10
        $x_10_4 = "ReadProcessMemory" ascii //weight: 10
        $x_10_5 = "NtAllocateVirtualMemory" ascii //weight: 10
        $x_1_6 = "AdjustTokenPrivileges" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_10_*))) or
            (all of ($x*))
        )
}

