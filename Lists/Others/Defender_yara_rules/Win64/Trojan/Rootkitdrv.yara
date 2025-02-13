rule Trojan_Win64_Rootkitdrv_A_2147651177_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Rootkitdrv.A"
        threat_id = "2147651177"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Rootkitdrv"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "G:\\git\\rk\\rk\\_OUT\\HlpSYS64.pdb" ascii //weight: 1
        $x_1_2 = "IPInjectPkt" ascii //weight: 1
        $x_1_3 = "KdDisableDebugger" wide //weight: 1
        $x_1_4 = "C:\\Windows\\system32\\drivers\\beep.sys" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Rootkitdrv_A_2147651177_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Rootkitdrv.A"
        threat_id = "2147651177"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Rootkitdrv"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 46 75 6e 63 00 00 00 45 78 70 6f 72 74 46 75 6e 63 00 [0-138] 68 65 61 64 4c 69 62 00}  //weight: 1, accuracy: Low
        $x_1_2 = {5c 00 44 00 65 00 76 00 69 00 63 00 65 00 5c 00 50 00 4e 00 54 00 46 00 49 00 4c 00 54 00 45 00 52 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {54 68 33 4e 00}  //weight: 1, accuracy: High
        $x_1_4 = {61 6d 64 36 34 5c 61 6d 64 36 34 5c 50 6f 69 6e 74 46 69 6c 74 65 72 2e 70 64 62 00}  //weight: 1, accuracy: High
        $x_1_5 = {3a c3 74 1e b8 4d 5a 00 00 66 3b 07 75 14 48 63 57 3c 48 03 d7 81 3a 50 45 00 00 48 0f 45 d3 48 8b da 48 8b c3 48 8b 5c 24 30}  //weight: 1, accuracy: High
        $x_1_6 = {49 3b f7 74 1d 81 3e 52 53 44 53 75 15 48 83 c9 ff 33 c0 48 8d 7e 18 f2 ae 48 f7 d1 48 2b cb 4c 8b f1 48 8b 4d 18 45 8b e7 e8}  //weight: 1, accuracy: Low
        $x_1_7 = {c7 44 24 28 80 00 00 00 c7 44 24 20 03 00 00 00 ff 15 ?? ?? ?? ?? 48 8b f8 48 85 c0 74 21 4c 8d 4c 24 48 4c 8d 44 24 40 48 8d 54 24 50 48 8b c8 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win64_Rootkitdrv_B_2147750110_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Rootkitdrv.B"
        threat_id = "2147750110"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Rootkitdrv"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "200"
        strings_accuracy = "High"
    strings:
        $x_1000_1 = "C:\\Users\\Mikhail\\Desktop\\Robnhold\\x64\\Win7Release\\Robbnhold.pdb" ascii //weight: 1000
        $x_100_2 = "\\Device\\Robnhold" ascii //weight: 100
        $x_100_3 = "\\DosDevices\\Robnhold" ascii //weight: 100
        $x_1_4 = "ZwTerminateProcess" ascii //weight: 1
        $x_1_5 = "ZwDeleteFile" ascii //weight: 1
        $x_1_6 = "ZwSetInformationFile" ascii //weight: 1
        $x_1_7 = "ZwClose" ascii //weight: 1
        $x_1_8 = "ZwQueryInformationFile" ascii //weight: 1
        $x_1_9 = "ZwCreateFile" ascii //weight: 1
        $x_1_10 = "IofCallDriver" ascii //weight: 1
        $x_1_11 = "IoCreateFileSpecifyDeviceObjectHint" ascii //weight: 1
        $x_1_12 = "KeAttachProcess" ascii //weight: 1
        $x_1_13 = "PsProcessType" ascii //weight: 1
        $x_1_14 = "PsAcquireProcessExitSynchronization" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_100_*))) or
            ((1 of ($x_1000_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_Rootkitdrv_LKB_2147822411_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Rootkitdrv.LKB!dha"
        threat_id = "2147822411"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Rootkitdrv"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Hid_StealthMode" wide //weight: 1
        $x_1_2 = "Hid_HideFsDirs" wide //weight: 1
        $x_1_3 = "Hid_HideFsFiles" wide //weight: 1
        $x_1_4 = "Hid_HideRegKeys" wide //weight: 1
        $x_1_5 = "Hid_HideRegValues" wide //weight: 1
        $x_2_6 = "\\Device\\HiddenGate" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

