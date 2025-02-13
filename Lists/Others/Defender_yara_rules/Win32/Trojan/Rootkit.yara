rule Trojan_Win32_Rootkit_F_2147510223_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rootkit.F"
        threat_id = "2147510223"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rootkit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "ntoskrnl.exe" ascii //weight: 10
        $x_2_2 = ".xdata" ascii //weight: 2
        $x_1_3 = {40 8d 48 ff 81 f9 02 01 00 00 0f 82}  //weight: 1, accuracy: High
        $x_1_4 = {0f 85 14 00 00 00 8b 45 f4 8b 04 85 bc 42 00 10 a3 c4 42 00 10}  //weight: 1, accuracy: High
        $x_1_5 = {8d 04 85 c8 42 00 10 01 10 41 83 f9 04}  //weight: 1, accuracy: High
        $x_1_6 = {a1 c4 42 00 10 68 48 42 00 10 ff d0 89 45 f8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 4 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Rootkit_F_2147510223_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rootkit.F"
        threat_id = "2147510223"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rootkit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "TPOC Rootkit" ascii //weight: 1
        $x_1_2 = {8d 44 00 02 50 8d 85 ?? ?? ff ff 50 68 04 20 22 00 ff 35 ?? ?? 40 00}  //weight: 1, accuracy: Low
        $x_1_3 = {8d 44 00 02 50 8d 85 ?? ?? ff ff 50 68 08 20 22 00 ff 35 ?? ?? 40 00 ff 15 ?? ?? 40 00 eb 10}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Rootkit_L_2147598269_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rootkit.L"
        threat_id = "2147598269"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rootkit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 57 ff 15 ?? ?? ?? ?? 85 c0 0f 84 ?? ?? ?? ?? 8b ff f6 ?? ?? ?? ?? 00 00 10 0f ?? ?? ?? 00 00 e8 ?? ?? 00 00 8b 0d ?? ?? ?? ?? 99 f7 f9 a1 ?? ?? ?? ?? 3b c2 7d 08 3b c1 0f}  //weight: 1, accuracy: Low
        $x_1_2 = {68 c8 00 00 00 ff d3 8b ?? ?? ?? 8b 0d ?? ?? ?? ?? 40 3b c8 89 ?? ?? ?? 7e 26 8b ?? ?? ?? 6a 03 ff d3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Rootkit_R_2147600463_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rootkit.R"
        threat_id = "2147600463"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rootkit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "ZwLoadDriver" ascii //weight: 1
        $x_1_2 = "KeServiceDescriptorTable" ascii //weight: 1
        $x_1_3 = "\\??\\C:\\WINDOWS\\SYSTEM32\\win32_rkt.sys" wide //weight: 1
        $x_1_4 = "\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Services\\DMusic" wide //weight: 1
        $x_1_5 = "\\drivers\\DMusic.sys" wide //weight: 1
        $x_1_6 = "g_rkt" wide //weight: 1
        $x_1_7 = {8d 54 36 1e 6a 00 89 44 24 24 66 89 4c 24 20 66 89 54 24 22 6a 60 6a 02 6a 00 6a 00 6a 00 8d 44 24 54 50 8d 4c 24 40 51 68 80 00 10 40 8d 54 24 38 52 ff d3}  //weight: 1, accuracy: High
        $x_1_8 = {8b c8 03 0d ?? ?? 01 00 83 ca ff e8 ?? ?? ff ff 3d 5b f0 6a c7 74 15 3d 45 30 34 01 74 0e 3d 45 d0 fa 58 74 07 5d ff 25 14 09 01 00 e8 ?? ?? ff ff b8 34 00 00 c0 5d c2 2c 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Rootkit_AF_2147604903_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rootkit.AF"
        threat_id = "2147604903"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rootkit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2035"
        strings_accuracy = "Low"
    strings:
        $x_1000_1 = {01 00 6a 00 6a 00 6a 00 6a 00 8d 85 a0 fd ff ff 50 ff 15 ?? ?? 01 00 89 85 94 fd ff ff}  //weight: 1000, accuracy: Low
        $x_1000_2 = {8d 85 34 ff ff ff 50 6a 01 6a 00 68 00 ?? 00 00 8d 85 8c fd ff ff 50 6a 00 ff 75 08 ff 15 ?? ?? 01 00 89 85 94 fd ff ff}  //weight: 1000, accuracy: Low
        $x_1000_3 = {83 bd 34 ff ff ff 00 74 ?? ff b5 34 ff ff ff ff 15 ?? ?? 01 00}  //weight: 1000, accuracy: Low
        $x_1000_4 = {50 68 3f 00 0f 00 8d 45 f4 50 ff 15 ?? ?? 01 00 89 45 e4}  //weight: 1000, accuracy: Low
        $x_1000_5 = {8d 45 e8 50 ff 75 fc ff 75 f8 6a 01 8d 45 ec 50 ff 75 f4 ff 15 ?? ?? 01 00 89 45 e4}  //weight: 1000, accuracy: Low
        $x_1_6 = "ZwCreateFile" ascii //weight: 1
        $x_1_7 = "PsCreateSystemThread" ascii //weight: 1
        $x_1_8 = "KeInsertQueueApc" ascii //weight: 1
        $x_1_9 = "IoDeleteSymbolicLink" ascii //weight: 1
        $x_1_10 = "GetSystemDirectoryW" ascii //weight: 1
        $x_1_11 = "ZwOpenKey" ascii //weight: 1
        $x_1_12 = "IoAllocateMdl" ascii //weight: 1
        $x_1_13 = "IoCreateDevice" ascii //weight: 1
        $x_1_14 = "strncmp" ascii //weight: 1
        $x_1_15 = "ZwQueryInformationFile" ascii //weight: 1
        $x_1_16 = "KeStackAttachProcess" ascii //weight: 1
        $x_1_17 = "KeSetEvent" ascii //weight: 1
        $x_1_18 = "ZwAllocateVirtualMemory" ascii //weight: 1
        $x_1_19 = "ntoskrnl.exe" ascii //weight: 1
        $x_1_20 = "ZwMapViewOfSection" ascii //weight: 1
        $x_1_21 = "ZwClose" ascii //weight: 1
        $x_1_22 = "KeUnstackDetachProcess" ascii //weight: 1
        $x_1_23 = "ZwCreateSection" ascii //weight: 1
        $x_1_24 = "KeInitializeApc" ascii //weight: 1
        $x_1_25 = "DeleteFileW" ascii //weight: 1
        $x_1_26 = "wcscpy" ascii //weight: 1
        $x_1_27 = "ImagePath" wide //weight: 1
        $x_1_28 = "LoadLibraryW" ascii //weight: 1
        $x_1_29 = "ZwUnmapViewOfSection" ascii //weight: 1
        $x_1_30 = "MmGetSystemRoutineAddress" ascii //weight: 1
        $x_1_31 = "PsGetVersion" ascii //weight: 1
        $x_1_32 = "IoDeleteDevice" ascii //weight: 1
        $x_1_33 = "IoFreeMdl" ascii //weight: 1
        $x_1_34 = "ExAllocatePoolWithTag" ascii //weight: 1
        $x_1_35 = "ZwQueryValueKey" ascii //weight: 1
        $x_1_36 = "KeInitializeEvent" ascii //weight: 1
        $x_1_37 = "MmUnlockPages" ascii //weight: 1
        $x_1_38 = "ZwOpenFile" ascii //weight: 1
        $x_1_39 = "MmProbeAndLockPages" ascii //weight: 1
        $x_1_40 = "ZwWriteFile" ascii //weight: 1
        $x_1_41 = "IofCompleteRequest" ascii //weight: 1
        $x_1_42 = "IoGetCurrentProcess" ascii //weight: 1
        $x_1_43 = "IoCreateSymbolicLink" ascii //weight: 1
        $x_1_44 = "lstrcatW" ascii //weight: 1
        $x_1_45 = "ZwReadFile" ascii //weight: 1
        $x_1_46 = "MmMapLockedPagesSpecifyCache" ascii //weight: 1
        $x_1_47 = "_stricmp" ascii //weight: 1
        $x_1_48 = "KeWaitForSingleObject" ascii //weight: 1
        $x_1_49 = "_except_handler3" ascii //weight: 1
        $x_1_50 = "RtlInitUnicodeString" ascii //weight: 1
        $x_1_51 = "ZwOpenProcess" ascii //weight: 1
        $x_1_52 = "PsTerminateSystemThread" ascii //weight: 1
        $x_1_53 = "wcscat" ascii //weight: 1
        $x_1_54 = "h.rdata" ascii //weight: 1
        $x_1_55 = "H.data" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1000_*) and 35 of ($x_1_*))) or
            ((3 of ($x_1000_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Rootkit_C_2147609451_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rootkit.C"
        threat_id = "2147609451"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rootkit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {66 c7 45 a4 6e 00 66 c7 45 a6 6b 00 66 c7 45 aa 3e 00 66 c7 45 ac 33 00 66 c7 45 ae 36 00 66 c7 45 b0 30 00 66 c7 45 b2 3c 00 66 c7 45 b4 2f 00 66 89 55 b6 66 c7 45 b8 3e 00}  //weight: 1, accuracy: High
        $x_1_2 = {68 40 1f 00 00 6a 02 ff 76 20 ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Rootkit_C_2147616224_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rootkit.gen!C"
        threat_id = "2147616224"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rootkit"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {6a 04 52 68 4b e1 22 00 50}  //weight: 3, accuracy: High
        $x_3_2 = {6a 66 51 e8}  //weight: 3, accuracy: High
        $x_3_3 = {81 e5 00 f0 00 00 81 fd 00 30 00 00}  //weight: 3, accuracy: High
        $x_3_4 = "KeServiceDescriptorTable" ascii //weight: 3
        $x_1_5 = "RESSDTDOS" ascii //weight: 1
        $x_1_6 = "Software\\Microsoft\\Windows\\CurrentVersion\\Setup\\poop" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Rootkit_GF_2147619084_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rootkit.GF"
        threat_id = "2147619084"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rootkit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 04 01 00 00 68 05 01 00 00 8d 4d f8}  //weight: 1, accuracy: High
        $x_1_2 = {68 3f 00 0f 00 6a 00 6a 00 ff 15}  //weight: 1, accuracy: High
        $x_1_3 = {6a 00 68 80 00 00 00 6a 03 6a 00 6a 00 68 00 00 00 c0 8d 4d f4 e8 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? 89 45 fc 83 7d fc ff 75 50}  //weight: 1, accuracy: Low
        $x_1_4 = "processhide.sys" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Rootkit_D_2147619328_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rootkit.D"
        threat_id = "2147619328"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rootkit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "if exist %1 goto Redo" ascii //weight: 1
        $x_1_2 = "del /f /q %0" ascii //weight: 1
        $x_1_3 = "%s\\drivers\\%s.sys" ascii //weight: 1
        $x_1_4 = "%s Bus Extender" ascii //weight: 1
        $x_1_5 = "%s\\CurrentControlSet\\Services\\%s" ascii //weight: 1
        $x_1_6 = "tsrIde" ascii //weight: 1
        $x_1_7 = "%c%c%c%c%c%c%c%c" ascii //weight: 1
        $x_1_8 = "%s\\ntdll.dll" ascii //weight: 1
        $x_1_9 = "IDE MiniPort" ascii //weight: 1
        $x_1_10 = "HELOWOLD" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Rootkit_D_2147619328_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rootkit.D"
        threat_id = "2147619328"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rootkit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "HELOWOLD" ascii //weight: 1
        $x_1_2 = "tsrIde" wide //weight: 1
        $x_1_3 = "SystemRoot\\System32\\vs_mon.dll" wide //weight: 1
        $x_1_4 = "http://www.9aaa.com" wide //weight: 1
        $x_1_5 = {43 00 6f 00 6d 00 70 00 61 00 6e 00 79 00 4e 00 61 00 6d 00 65 00 00 00 00 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 20 00 43 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Rootkit_HI_2147627945_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rootkit.HI"
        threat_id = "2147627945"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rootkit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 08 00 22 00 ff 35 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 81 7d f4 bb a4 04 00 75 08 6a 01 58}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 40 68 00 10 00 00 68 d4 01 00 00 53 57 ff 15 ?? ?? ?? ?? 8b f0 3b f3 74 5e 53 68 d0 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {80 7f 09 00 74 21 8b 46 64 8b 15 ?? ?? ?? ?? 8d 0c 40 8b 46 68 8b 4c ca 0c 8d 04 80 8d 04 81 8b cb 50 e8}  //weight: 1, accuracy: Low
        $x_1_4 = {eb 0f 83 25 d8 ?? ?? 10 00 b8 ?? ?? 00 10 c3 33 f6 83 4d fc ff 39 35 ?? ?? 01 10 0f 84 ?? ?? 00 00 e8 ?? ?? 00 00 8b 0d ?? ?? 01 10 6a 50 ff 35 ?? ?? 01 10 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Rootkit_EA_2147888612_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rootkit.EA!MTB"
        threat_id = "2147888612"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rootkit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "qovxk\\wqdtbmac.pdb" ascii //weight: 1
        $x_1_2 = "NTOSKRNL.exe" ascii //weight: 1
        $x_1_3 = "Okeggram Initiuliz" ascii //weight: 1
        $x_1_4 = "IoDeleteDevice" ascii //weight: 1
        $x_1_5 = "IoFreeMdl" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Rootkit_GTL_2147919927_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rootkit.GTL!MTB"
        threat_id = "2147919927"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rootkit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {f0 d7 45 fb 86 4a fb f5 b0 c8 fd 29 a7 38 66 24 80 e2 31 59 a3 b2 e0 52 7e a2 40 6a 37 aa c8 c0 be b7 6c}  //weight: 5, accuracy: High
        $x_5_2 = {45 c4 50 51 56 56 56 56 ff 75 e4 6a 03 ff 15 20 e2 01 00 8b f8 89 7d 0c 3b fe 75 08 53 e8 af 43 00 00 eb 93 8b 75 18 33 c9 3b f1 74 74 51 51 51 56 ff}  //weight: 5, accuracy: High
        $x_1_3 = "\\httprdr\\tdxflt\\objfre_wxp_x86\\i386\\TdxFlt_i386.pdb" ascii //weight: 1
        $x_1_4 = "ExAcquireFastMutex" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Rootkit_EK_2147920391_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rootkit.EK!MTB"
        threat_id = "2147920391"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rootkit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "23"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {6a 40 57 89 45 f8 8d 45 f8 50 53 8d 45 f4 50 ff 75 08}  //weight: 10, accuracy: High
        $x_5_2 = "cnzz_url" ascii //weight: 5
        $x_5_3 = "searching_magic_url" ascii //weight: 5
        $x_1_4 = "8.8.8.8" ascii //weight: 1
        $x_1_5 = "hpsafe.pdb" ascii //weight: 1
        $x_1_6 = "Explorer.exe" ascii //weight: 1
        $x_1_7 = "recount" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

