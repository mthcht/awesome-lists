rule VirTool_WinNT_Fursto_F_2147598221_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Fursto.F"
        threat_id = "2147598221"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Fursto"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {53 54 41 52 54 45 44 [0-2] 49 6e 73 74 61 6c 6c 48 6f 6f 6b 73 3a [0-4] 53 55 43 43 45 53 53 [0-2] 69 6e 73 74 61 6c 6c 48 6f 6f 6b 73 3a [0-4] 46 41 49 4c 45 44 [0-4] 49 6e 73 74 61 6c 6c 48 6f 6f 6b 73 3a}  //weight: 4, accuracy: Low
        $x_4_2 = {53 54 41 52 54 45 44 [0-2] 52 65 68 6f 6f 6b 20 74 68 72 65 61 64 3a [0-4] 45 58 49 54 [0-5] 52 65 68 6f 6f 6b 20 74 68 72 65 61 64 3a [0-4] 52 45 48 4f 4f 4b 45 44 [0-4] 52 65 68 6f 6f 6b 20 74 68 72 65 61 64 3a [0-4] 46 41 49 4c 45 44 [0-4] 52 65 68 6f 6f 6b 20 74 68 72 65 61 64 3a [0-4] 45 58 43 45 50 54 49 4f 4e [0-4] 52 65 68 6f 6f 6b 20 74 68 72 65 61 64}  //weight: 4, accuracy: Low
        $x_4_3 = {53 54 41 52 54 45 44 [0-2] 52 65 73 6f 6c 76 65 20 74 68 72 65 61 64 3a [0-8] 45 58 49 54 [0-8] 52 65 73 6f 6c 76 65 20 74 68 72 65 61 64 3a [0-8] 45 58 43 45 50 54 49 4f 4e [0-4] 47 65 74 44 6f 73 4e 61 6d 65 54 68 72 65 61 64 50 72 6f 63 3a}  //weight: 4, accuracy: Low
        $x_1_4 = "LoadOptions: driver image file path =" ascii //weight: 1
        $x_1_5 = "LoadOptions: driver directory [NT] =" ascii //weight: 1
        $x_1_6 = "LoadOptions: driver directory [DOS] =" ascii //weight: 1
        $x_1_7 = "GetKernelCallsAddresses (Windows Server 2003, build 3790):" ascii //weight: 1
        $x_1_8 = "GetKernelCallsAddresses (Windows XP, build 2600):" ascii //weight: 1
        $x_1_9 = "GetKernelCallsAddresses (Windows 2000, build 2195):" ascii //weight: 1
        $x_1_10 = "ERROR, GetKernelCallsAddresses() failed" ascii //weight: 1
        $x_1_11 = "WARNING, CreateDosPathResolveThread() failed" ascii //weight: 1
        $x_1_12 = "FileInformationClass != FileBothDirectoryInformation" ascii //weight: 1
        $x_1_13 = "NtDeleteFile [protected]:" ascii //weight: 1
        $x_1_14 = "NtQueryAttributesFile [protected]:" ascii //weight: 1
        $x_1_15 = "NtQueryFullAttributesFile [protected]:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 12 of ($x_1_*))) or
            ((2 of ($x_4_*) and 8 of ($x_1_*))) or
            ((3 of ($x_4_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_WinNT_Fursto_G_2147598223_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Fursto.G"
        threat_id = "2147598223"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Fursto"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = "\\Registry\\Machine\\Software\\Microsoft\\AppCert" ascii //weight: 4
        $x_2_2 = "\\Device\\__HD2__" ascii //weight: 2
        $x_2_3 = "\\DosDevices\\__HD2__" ascii //weight: 2
        $x_1_4 = {68 64 5f 73 65 6c 66 2e 63 66 67 00}  //weight: 1, accuracy: High
        $x_1_5 = {68 64 5f 66 69 6c 65 73 2e 63 66 67 00}  //weight: 1, accuracy: High
        $x_1_6 = {68 64 5f 64 69 72 73 2e 63 66 67 00}  //weight: 1, accuracy: High
        $x_1_7 = {68 64 5f 72 6b 65 79 73 2e 63 66 67 00}  //weight: 1, accuracy: High
        $x_1_8 = {68 64 5f 72 76 61 6c 73 2e 63 66 67 00}  //weight: 1, accuracy: High
        $x_8_9 = {eb 60 8b 45 f8 50 e8 ?? ?? 00 00 85 c0 75 15 c7 05 ?? ?? ?? 00 00 00 00 00 8d 4d f8 51 e8 ?? ?? 00 00 eb 3e 68 ?? ?? 01 00 e8 ?? ?? 00 00 50 6a 01}  //weight: 8, accuracy: Low
        $x_8_10 = {83 e9 01 89 4d c4 83 7d c4 0b 77 53 8b 55 c4 0f b6 82 ?? ?? ?? 00 ff 24 85 ?? ?? ?? 00 68}  //weight: 8, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_4_*) and 4 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_2_*))) or
            ((1 of ($x_8_*))) or
            (all of ($x*))
        )
}

