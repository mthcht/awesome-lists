rule Backdoor_WinNT_Farfli_A_2147595018_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:WinNT/Farfli.A!sys"
        threat_id = "2147595018"
        type = "Backdoor"
        platform = "WinNT: WinNT"
        family = "Farfli"
        severity = "Critical"
        info = "sys: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {fa 8d 45 fc 50 e8 ?? ff ff ff 8b 0d ?? ?? 01 00 a1 ?? ?? 01 00 8b 51 01 8b 30 8b 14 96 89 15 ?? ?? 01 00 8b 49 01 8b 00 c7 04 88 ?? ?? 01 00 ff 75 fc e8 ?? ff ff ff fb}  //weight: 1, accuracy: Low
        $x_1_2 = {8d 45 e8 68 00 80 00 00 50 6a 04 57 ff 15 ?? ?? 01 00 85 c0 7c ?? 8d 45 e0 68 ?? ?? 01 00 50 ff d6 8d 45 e8 50 8d 45 e0 50 ff 15 ?? ?? 01 00 8b f0 85 f6 7d 0d ff 75 fc ff 15}  //weight: 1, accuracy: Low
        $x_1_3 = {8d 45 e8 68 00 80 00 00 50 6a 04 [0-3] ff 15 ?? ?? 01 00 3b ?? 7c ?? 8d 45 e0 68 ?? ?? 01 00 50 ff ?? 8d 45 e8 50 8d 45 e0 50 ff 15 ?? ?? 01 00 8b ?? 3b ?? 7d 0d ff 75 fc ff 15}  //weight: 1, accuracy: Low
        $x_1_4 = "KeServiceDescriptorTable" ascii //weight: 1
        $x_1_5 = "ZwSetValueKey" ascii //weight: 1
        $x_1_6 = "ObReferenceObjectByHandle" ascii //weight: 1
        $x_1_7 = "ObfDereferenceObject" ascii //weight: 1
        $x_1_8 = "ZwDeleteValueKey" ascii //weight: 1
        $x_1_9 = "ZwWriteFile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (8 of ($x*))
}

rule Backdoor_WinNT_Farfli_B_2147595019_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:WinNT/Farfli.B!sys"
        threat_id = "2147595019"
        type = "Backdoor"
        platform = "WinNT: WinNT"
        family = "Farfli"
        severity = "Critical"
        info = "sys: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 ff d7 8d 45 fc 89 75 fc 50 6a 01 5b 8d 45 ec 53 56 68 00 80 00 00 50 56 ff 75 08 ff 15 ?? ?? 01 00 3b c6 0f 8c ?? 00 00 00 8d 45 e4 68 ?? ?? 01 00 50 ff d7 8d 45 ec 50 8d 45 e4 50 ff 15 ?? ?? 01 00 8b f8 3b fe 7d 10 ff 75 fc ff 15 ?? ?? 01 00 8b c7}  //weight: 1, accuracy: Low
        $x_1_2 = {89 7d e0 89 75 dc 89 75 e4 89 75 e8 ff 15 ?? ?? 01 00 8b 3d ?? ?? 01 00 85 c0 7c 40 6a 04 68 00 00 10 00 8d 45 fc 6a 01 50 56 68 00 10 00 00 56 68 ?? ?? 01 00 6a ff ff 35 ?? ?? 01 00 89 75 fc ff 15 ?? ?? 01 00 85 c0 7c 04 b0 01 eb 18 ff 35 ?? ?? 01 00 89 35 ?? ?? 01 00 ff d7 ff 35 ?? ?? 01 00 ff d7 32 c0 5f 5e 5b c9 c3 cc}  //weight: 1, accuracy: Low
        $x_1_3 = {ab ab ab ab ab 8d 45 f4 56 89 45 dc 56 33 c0 8d 7d f0 6a 21 89 75 ec 6a 01 6a 01 ab 68 80 00 00 00 8d 45 ec 56 50 8d 45 d4 c7 45 d4 18 00 00 00 50 8d 45 fc 68 80 00 10 00 50 89 75 d8 c7 45 e0 40 02 00 00 89 75 e4 89 75 e8 89 75 fc ff 15}  //weight: 1, accuracy: High
        $x_1_4 = "KeDelayExecutionThread" ascii //weight: 1
        $x_1_5 = "ZwMapViewOfSection" ascii //weight: 1
        $x_1_6 = "ZwCreateSection" ascii //weight: 1
        $x_1_7 = "IoDeleteDevice" ascii //weight: 1
        $x_1_8 = "ntoskrnl.exe" ascii //weight: 1
        $x_1_9 = "ZwCreateKey" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule Backdoor_WinNT_Farfli_C_2147596675_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:WinNT/Farfli.C!sys"
        threat_id = "2147596675"
        type = "Backdoor"
        platform = "WinNT: WinNT"
        family = "Farfli"
        severity = "Critical"
        info = "sys: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff 75 0c ff 75 08 e8 ?? fc ff ff 84 c0 58 8b e5 5d 74 11 aa bb cc dd ee ff aa aa aa aa ea bb bb bb bb 08 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_WinNT_Farfli_E_2147601599_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:WinNT/Farfli.E!sys"
        threat_id = "2147601599"
        type = "Backdoor"
        platform = "WinNT: WinNT"
        family = "Farfli"
        severity = "Critical"
        info = "sys: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_8_1 = {38 08 74 11 3b 4c 24 ?? 7d 0b 80 04 01 ?? 41 80 3c 01 00 75 ef [0-1] c2 08 00}  //weight: 8, accuracy: Low
        $x_5_2 = {3d 24 0c 0b 83 74 29}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_WinNT_Farfli_E_2147601599_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:WinNT/Farfli.E!sys"
        threat_id = "2147601599"
        type = "Backdoor"
        platform = "WinNT: WinNT"
        family = "Farfli"
        severity = "Critical"
        info = "sys: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 e4 8b 10 a1 ?? ?? ?? ?? 39 50 08 77 07 bf 0d 00 00 c0 eb 3e 8b 08 fa 0f 20 c0 25 ff ff fe ff 0f 22 c0 8b 03 89 04 91 0f 20 c0 0d 00 00 01 00 0f 22 c0 fb}  //weight: 1, accuracy: Low
        $x_1_2 = "KeServiceDescriptorTable" ascii //weight: 1
        $x_1_3 = {83 c7 fd eb ?? 83 3d ?? ?? 01 00 ?? 76 ?? ff 15 ?? ?? 01 00 a1 ?? ?? 01 00 8b 38 83 [0-32] fa 0f 20 c0 25 ff ff fe ff 0f 22 c0 8b ?? e4 8b 00 89 04 ?? 0f 20 c0 0d 00 00 01 00 0f 22 c0 fb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Backdoor_WinNT_Farfli_F_2147607366_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:WinNT/Farfli.F!sys"
        threat_id = "2147607366"
        type = "Backdoor"
        platform = "WinNT: WinNT"
        family = "Farfli"
        severity = "Critical"
        info = "sys: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 c7 45 ee 73 00 66 c7 45 f0 25 00 66 c7 45 f2 73 00 [0-31] 83 c4 14 83 7d 08 01 75}  //weight: 1, accuracy: Low
        $x_1_2 = {8d 45 f8 50 6a 00 6a 00 c7 45 f8 00 1f 0a fa ff 15 ?? ?? 01 00 6a 01 e8 ?? ?? ?? ?? 6a 01 ff 15 ?? ?? 01 00 c9}  //weight: 1, accuracy: Low
        $x_1_3 = {38 5d 10 56 57 0f 84 ?? ?? 00 00 83 7d 0c 14 0f 82 ?? ?? 00 00 8d 45 10 89 5d 10 50 ff 75 0c ff 15 ?? ?? 01 00 85 c0 0f 8c ?? ?? 00 00 33 c0 8d 7d f1 88 5d f0 8b 4d 10 ab ab ab 66 ab}  //weight: 1, accuracy: Low
        $x_1_4 = {5a 00 77 00 45 00 6e 00 75 00 6d 00 65 00 72 00 61 00 74 00 65 00 4b 00 65 00 79 00 00 00 5a 00 77 00 43 00 6c 00 6f 00 73 00 65 00 00 00 5a 00 77}  //weight: 1, accuracy: High
        $x_1_5 = "PsSetCreateProcessNotifyRoutine" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_WinNT_Farfli_H_2147609258_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:WinNT/Farfli.H!sys"
        threat_id = "2147609258"
        type = "Backdoor"
        platform = "WinNT: WinNT"
        family = "Farfli"
        severity = "Critical"
        info = "sys: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "145"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {74 4d 8b 46 3c 83 65 08 00 8b 44 30 78 03 c6}  //weight: 5, accuracy: High
        $x_5_2 = {f3 ab 66 ab aa 8d 45 f8 50 8d 45 fc 6a 04 50 6a 0b ff d6 3d 04 00 00 c0}  //weight: 5, accuracy: High
        $x_100_3 = {89 7d e0 89 75 dc 89 75 e4 89 75 e8 ff 15 ?? ?? 01 00 8b 3d ?? ?? 01 00 85 c0 7c 40 6a 04 68 00 00 10 00 8d 45 fc 6a 01 50 56 68 00 10 00 00 56 68 ?? ?? 01 00 6a ff ff 35 ?? ?? 01 00 89 75 fc ff 15 ?? ?? 01 00 85 c0 7c 04 b0 01 eb 18 ff 35 ?? ?? 01 00 89 35 ?? ?? 01 00 ff d7 ff 35 ?? ?? 01 00 ff d7 32 c0 5f 5e 5b c9 c3}  //weight: 100, accuracy: Low
        $x_100_4 = {53 55 56 57 ff 15 ?? 02 01 00 8b e8 33 db be ?? ?? 01 00 8b fe 83 c9 ff 33 c0 f2 ae f7 d1 49 8d 04 2b 51 50 56 ff ?? ?? 02 01 00 83 c4 0c 85 c0 74 10 43 81 fb 00 30 00 00 7c d8 33 c0 5f 5e 5d 5b c3 8b c3 eb f7}  //weight: 100, accuracy: Low
        $x_1_5 = "ZwEnumerateKey" ascii //weight: 1
        $x_1_6 = "ZwSetValueKey" ascii //weight: 1
        $x_1_7 = "ZwCreateKey" ascii //weight: 1
        $x_1_8 = "ZwUnmapViewOfSection" ascii //weight: 1
        $x_1_9 = "ZwQuerySystemInformation" ascii //weight: 1
        $x_1_10 = "ZwCreateFile" ascii //weight: 1
        $x_1_11 = "ZwOpenKey" ascii //weight: 1
        $x_1_12 = "ZwMapViewOfSection" ascii //weight: 1
        $x_1_13 = "ZwClose" ascii //weight: 1
        $x_1_14 = "ZwCreateSection" ascii //weight: 1
        $x_1_15 = "IoGetCurrentProcess" ascii //weight: 1
        $x_1_16 = "IoCreateSymbolicLink" ascii //weight: 1
        $x_1_17 = "IoCreateDevice" ascii //weight: 1
        $x_1_18 = "IoRegisterDriverReinitialization" ascii //weight: 1
        $x_1_19 = "IoDeleteDevice" ascii //weight: 1
        $x_1_20 = "IofCompleteRequest" ascii //weight: 1
        $x_1_21 = "\\KabCleanner" wide //weight: 1
        $x_1_22 = "\\registry\\machine\\system\\currentcontrolset\\services\\" wide //weight: 1
        $x_1_23 = "\\registry\\machine\\software\\microsoft\\windows\\currentversion\\runonce" wide //weight: 1
        $x_1_24 = "\\SystemRoot" wide //weight: 1
        $x_1_25 = "\\SystemRoot\\system32\\drivers\\" wide //weight: 1
        $x_1_26 = "\\system32\\Rundll32.exe " wide //weight: 1
        $x_1_27 = "System32\\DRIVERS\\" wide //weight: 1
        $x_1_28 = "\\systemroot\\system32\\%s" ascii //weight: 1
        $x_1_29 = "systemroot" ascii //weight: 1
        $x_1_30 = "\\Device" wide //weight: 1
        $x_1_31 = "\\DosDevices" wide //weight: 1
        $x_1_32 = ".dll,DllUnregisterServer" wide //weight: 1
        $x_1_33 = "MmIsAddressValid" ascii //weight: 1
        $x_1_34 = "PsSetCreateProcessNotifyRoutine" ascii //weight: 1
        $x_1_35 = "KeDelayExecutionThread" ascii //weight: 1
        $x_1_36 = "ExAllocatePoolWithTag" ascii //weight: 1
        $x_1_37 = "KeServiceDescriptorTable" ascii //weight: 1
        $x_1_38 = "PsLookupProcessByProcessId" ascii //weight: 1
        $x_1_39 = "PsCreateSystemThread" ascii //weight: 1
        $x_1_40 = "PsTerminateSystemThread" ascii //weight: 1
        $x_1_41 = "MmGetSystemRoutineAddress" ascii //weight: 1
        $x_1_42 = "KeInitializeTimer" ascii //weight: 1
        $x_1_43 = ".text" ascii //weight: 1
        $x_1_44 = "h.data" ascii //weight: 1
        $x_1_45 = ".reloc" ascii //weight: 1
        $x_1_46 = "ntoskrnl.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 1 of ($x_5_*) and 40 of ($x_1_*))) or
            ((1 of ($x_100_*) and 2 of ($x_5_*) and 35 of ($x_1_*))) or
            ((2 of ($x_100_*))) or
            (all of ($x*))
        )
}

rule Backdoor_WinNT_Farfli_G_2147609259_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:WinNT/Farfli.G!sys"
        threat_id = "2147609259"
        type = "Backdoor"
        platform = "WinNT: WinNT"
        family = "Farfli"
        severity = "Critical"
        info = "sys: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "120"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {53 55 56 57 ff 15 ?? 02 01 00 8b e8 33 db be ?? ?? 01 00 8b fe 83 c9 ff 33 c0 f2 ae f7 d1 49 8d 04 2b 51 50 56 ff ?? ?? 02 01 00 83 c4 0c 85 c0 74 10 43 81 fb 00 30 00 00 7c d8 33 c0 5f 5e 5d 5b c3 8b c3 eb f7}  //weight: 100, accuracy: Low
        $x_2_2 = "ExAllocatePoolWithTag" ascii //weight: 2
        $x_2_3 = "KeDelayExecutionThread" ascii //weight: 2
        $x_2_4 = "MmGetSystemRoutineAddress" ascii //weight: 2
        $x_2_5 = "PsCreateSystemThread" ascii //weight: 2
        $x_2_6 = "IoGetCurrentProcess" ascii //weight: 2
        $x_2_7 = "PsGetVersion" ascii //weight: 2
        $x_2_8 = "IofCompleteRequest" ascii //weight: 2
        $x_2_9 = "IoRegisterDriverReinitialization" ascii //weight: 2
        $x_2_10 = "ZwOpenKey" ascii //weight: 2
        $x_2_11 = "ZwSetValueKey" ascii //weight: 2
        $x_2_12 = "ZwClose" ascii //weight: 2
        $x_2_13 = "IoCreateSymbolicLink" wide //weight: 2
        $x_2_14 = "IoDeleteDevice" wide //weight: 2
        $x_3_15 = "fCfJfZf[" ascii //weight: 3
        $x_3_16 = "fBfK[ZF" ascii //weight: 3
        $x_3_17 = "fSfRf" ascii //weight: 3
        $x_3_18 = "fBfK[Z[" ascii //weight: 3
        $x_5_19 = ".dll,DllUnregisterServer" wide //weight: 5
        $x_5_20 = "\\KabCleanner" wide //weight: 5
        $x_4_21 = "\\system32\\Rundll32.exe " wide //weight: 4
        $x_2_22 = "\\Device" wide //weight: 2
        $x_4_23 = "\\SystemRoot\\system32\\drivers\\" wide //weight: 4
        $x_1_24 = "\\DosDevices" wide //weight: 1
        $x_1_25 = "systemroot" wide //weight: 1
        $x_1_26 = "\\SystemRoot" wide //weight: 1
        $x_2_27 = "System32\\DRIVERS\\" wide //weight: 2
        $x_1_28 = "explorer.exe" ascii //weight: 1
        $x_4_29 = "ntoskrnl.exe" ascii //weight: 4
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 8 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_100_*) and 9 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_100_*) and 10 of ($x_2_*))) or
            ((1 of ($x_100_*) and 1 of ($x_3_*) and 7 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_100_*) and 1 of ($x_3_*) and 8 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_100_*) and 1 of ($x_3_*) and 9 of ($x_2_*))) or
            ((1 of ($x_100_*) and 2 of ($x_3_*) and 5 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_100_*) and 2 of ($x_3_*) and 6 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_100_*) and 2 of ($x_3_*) and 7 of ($x_2_*))) or
            ((1 of ($x_100_*) and 3 of ($x_3_*) and 4 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_100_*) and 3 of ($x_3_*) and 5 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_100_*) and 3 of ($x_3_*) and 6 of ($x_2_*))) or
            ((1 of ($x_100_*) and 4 of ($x_3_*) and 2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_100_*) and 4 of ($x_3_*) and 3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_100_*) and 4 of ($x_3_*) and 4 of ($x_2_*))) or
            ((1 of ($x_100_*) and 1 of ($x_4_*) and 6 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_100_*) and 1 of ($x_4_*) and 7 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_100_*) and 1 of ($x_4_*) and 8 of ($x_2_*))) or
            ((1 of ($x_100_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 5 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_100_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 6 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_100_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 7 of ($x_2_*))) or
            ((1 of ($x_100_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 3 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_100_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 4 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_100_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 5 of ($x_2_*))) or
            ((1 of ($x_100_*) and 1 of ($x_4_*) and 3 of ($x_3_*) and 2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_100_*) and 1 of ($x_4_*) and 3 of ($x_3_*) and 3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_100_*) and 1 of ($x_4_*) and 3 of ($x_3_*) and 4 of ($x_2_*))) or
            ((1 of ($x_100_*) and 1 of ($x_4_*) and 4 of ($x_3_*) and 4 of ($x_1_*))) or
            ((1 of ($x_100_*) and 1 of ($x_4_*) and 4 of ($x_3_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_100_*) and 1 of ($x_4_*) and 4 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_100_*) and 2 of ($x_4_*) and 4 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_100_*) and 2 of ($x_4_*) and 5 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_100_*) and 2 of ($x_4_*) and 6 of ($x_2_*))) or
            ((1 of ($x_100_*) and 2 of ($x_4_*) and 1 of ($x_3_*) and 3 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_100_*) and 2 of ($x_4_*) and 1 of ($x_3_*) and 4 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_100_*) and 2 of ($x_4_*) and 1 of ($x_3_*) and 5 of ($x_2_*))) or
            ((1 of ($x_100_*) and 2 of ($x_4_*) and 2 of ($x_3_*) and 1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_100_*) and 2 of ($x_4_*) and 2 of ($x_3_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_100_*) and 2 of ($x_4_*) and 2 of ($x_3_*) and 3 of ($x_2_*))) or
            ((1 of ($x_100_*) and 2 of ($x_4_*) and 3 of ($x_3_*) and 3 of ($x_1_*))) or
            ((1 of ($x_100_*) and 2 of ($x_4_*) and 3 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_100_*) and 2 of ($x_4_*) and 3 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_100_*) and 2 of ($x_4_*) and 4 of ($x_3_*))) or
            ((1 of ($x_100_*) and 3 of ($x_4_*) and 2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_100_*) and 3 of ($x_4_*) and 3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_100_*) and 3 of ($x_4_*) and 4 of ($x_2_*))) or
            ((1 of ($x_100_*) and 3 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_100_*) and 3 of ($x_4_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_100_*) and 3 of ($x_4_*) and 1 of ($x_3_*) and 3 of ($x_2_*))) or
            ((1 of ($x_100_*) and 3 of ($x_4_*) and 2 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_100_*) and 3 of ($x_4_*) and 2 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_100_*) and 3 of ($x_4_*) and 3 of ($x_3_*))) or
            ((1 of ($x_100_*) and 1 of ($x_5_*) and 6 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_100_*) and 1 of ($x_5_*) and 7 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_100_*) and 1 of ($x_5_*) and 8 of ($x_2_*))) or
            ((1 of ($x_100_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 4 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_100_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 5 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_100_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 6 of ($x_2_*))) or
            ((1 of ($x_100_*) and 1 of ($x_5_*) and 2 of ($x_3_*) and 3 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_100_*) and 1 of ($x_5_*) and 2 of ($x_3_*) and 4 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_100_*) and 1 of ($x_5_*) and 2 of ($x_3_*) and 5 of ($x_2_*))) or
            ((1 of ($x_100_*) and 1 of ($x_5_*) and 3 of ($x_3_*) and 1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_100_*) and 1 of ($x_5_*) and 3 of ($x_3_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_100_*) and 1 of ($x_5_*) and 3 of ($x_3_*) and 3 of ($x_2_*))) or
            ((1 of ($x_100_*) and 1 of ($x_5_*) and 4 of ($x_3_*) and 3 of ($x_1_*))) or
            ((1 of ($x_100_*) and 1 of ($x_5_*) and 4 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_100_*) and 1 of ($x_5_*) and 4 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_100_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 4 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_100_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 5 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_100_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 6 of ($x_2_*))) or
            ((1 of ($x_100_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_100_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_100_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 4 of ($x_2_*))) or
            ((1 of ($x_100_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_100_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_100_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 3 of ($x_2_*))) or
            ((1 of ($x_100_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 3 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_100_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 3 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_100_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 4 of ($x_3_*))) or
            ((1 of ($x_100_*) and 1 of ($x_5_*) and 2 of ($x_4_*) and 2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_100_*) and 1 of ($x_5_*) and 2 of ($x_4_*) and 3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_100_*) and 1 of ($x_5_*) and 2 of ($x_4_*) and 4 of ($x_2_*))) or
            ((1 of ($x_100_*) and 1 of ($x_5_*) and 2 of ($x_4_*) and 1 of ($x_3_*) and 4 of ($x_1_*))) or
            ((1 of ($x_100_*) and 1 of ($x_5_*) and 2 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_100_*) and 1 of ($x_5_*) and 2 of ($x_4_*) and 1 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_100_*) and 1 of ($x_5_*) and 2 of ($x_4_*) and 2 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_100_*) and 1 of ($x_5_*) and 2 of ($x_4_*) and 2 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_100_*) and 1 of ($x_5_*) and 2 of ($x_4_*) and 3 of ($x_3_*))) or
            ((1 of ($x_100_*) and 1 of ($x_5_*) and 3 of ($x_4_*) and 3 of ($x_1_*))) or
            ((1 of ($x_100_*) and 1 of ($x_5_*) and 3 of ($x_4_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_100_*) and 1 of ($x_5_*) and 3 of ($x_4_*) and 2 of ($x_2_*))) or
            ((1 of ($x_100_*) and 1 of ($x_5_*) and 3 of ($x_4_*) and 1 of ($x_3_*))) or
            ((1 of ($x_100_*) and 2 of ($x_5_*) and 3 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_100_*) and 2 of ($x_5_*) and 4 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_100_*) and 2 of ($x_5_*) and 5 of ($x_2_*))) or
            ((1 of ($x_100_*) and 2 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_100_*) and 2 of ($x_5_*) and 1 of ($x_3_*) and 3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_100_*) and 2 of ($x_5_*) and 1 of ($x_3_*) and 4 of ($x_2_*))) or
            ((1 of ($x_100_*) and 2 of ($x_5_*) and 2 of ($x_3_*) and 4 of ($x_1_*))) or
            ((1 of ($x_100_*) and 2 of ($x_5_*) and 2 of ($x_3_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_100_*) and 2 of ($x_5_*) and 2 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_100_*) and 2 of ($x_5_*) and 3 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_100_*) and 2 of ($x_5_*) and 3 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_100_*) and 2 of ($x_5_*) and 4 of ($x_3_*))) or
            ((1 of ($x_100_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_100_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_100_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 3 of ($x_2_*))) or
            ((1 of ($x_100_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 3 of ($x_1_*))) or
            ((1 of ($x_100_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_100_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_100_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_3_*))) or
            ((1 of ($x_100_*) and 2 of ($x_5_*) and 2 of ($x_4_*) and 2 of ($x_1_*))) or
            ((1 of ($x_100_*) and 2 of ($x_5_*) and 2 of ($x_4_*) and 1 of ($x_2_*))) or
            ((1 of ($x_100_*) and 2 of ($x_5_*) and 2 of ($x_4_*) and 1 of ($x_3_*))) or
            ((1 of ($x_100_*) and 2 of ($x_5_*) and 3 of ($x_4_*))) or
            (all of ($x*))
        )
}

