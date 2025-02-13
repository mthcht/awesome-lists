rule Ransom_Win32_Pyunsam_SA_2147760551_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Pyunsam.SA!MTB"
        threat_id = "2147760551"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Pyunsam"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "copy %temp%\\paying\\pay-to-unlock.txt %SystemDrive%" ascii //weight: 1
        $x_1_2 = "del /q /s /f %temp%\\paying\\pay-to-unlock.exe" ascii //weight: 1
        $x_1_3 = "Unlock Me After Payment" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Ransom_Win32_Pyunsam_DA_2147760620_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Pyunsam.DA!MTB"
        threat_id = "2147760620"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Pyunsam"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "rem *************** start of 'main'" ascii //weight: 1
        $x_1_2 = {25 73 79 73 74 65 6d 64 72 69 76 65 25 5c ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 5c 45 53 45 54 5c 45 53 45 54 20 4e 4f 44 33 32 20 41 6e 74 69 76 69 72 75 73 5c 63 61 6c 6c 6d 73 69 2e 65 78 65 22 20 2f 78 20 7b ?? ?? ?? ?? ?? ?? ?? ?? 2d ?? ?? ?? ?? 2d ?? ?? ?? ?? 2d ?? ?? ?? ?? 2d ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 7d 20 2f 71 75 69 65 74}  //weight: 1, accuracy: Low
        $x_1_3 = {25 73 79 73 74 65 6d 64 72 69 76 65 25 5c 57 69 6e 64 6f 77 73 5c 53 79 73 74 65 6d 33 32 5c 6d 73 69 65 78 65 63 2e 65 78 65 20 2f 78 20 7b ?? ?? ?? ?? ?? ?? ?? ?? 2d ?? ?? ?? ?? 2d ?? ?? ?? ?? 2d ?? ?? ?? ?? 2d ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 7d 20 2f 71 75 69 65 74}  //weight: 1, accuracy: Low
        $x_1_4 = {25 53 59 53 54 45 4d 44 52 49 56 45 25 5c ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 5c 41 76 69 72 61 5c 41 6e 74 69 56 69 72 20 44 65 73 6b 74 6f 70 5c 73 65 74 75 70 2e 65 78 65 22 20 2f 72 65 6d 73 69 6c 65 6e 74 6e 6f 72 65 62 6f 6f 74}  //weight: 1, accuracy: Low
        $x_1_5 = {25 73 79 73 74 65 6d 64 72 69 76 65 25 5c ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 5c 53 4d 41 44 41 56 5c 75 6e 69 6e 73 30 30 30 2e 65 78 65 22 20 2f 53 49 4c 45 4e 54}  //weight: 1, accuracy: Low
        $x_1_6 = {25 73 79 73 74 65 6d 64 72 69 76 65 25 5c ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 5c 41 56 47 5c 41 76 5c 61 76 67 6d 66 61 70 78 2e 65 78 65 22 20 2f 41 70 70 6d 6f 64 65 3d 53 65 74 75 70 20 2f 75 6e 69 6e 73 74 61 6c 6c 20 2f 75 69 6c 65 76 65 6c 3d 53 69 6c 65 6e 74 20 2f 64 6f 6e 74 72 65 73 74 61 72 74}  //weight: 1, accuracy: Low
        $x_1_7 = "%ProgramFiles%\\McAfee Security Scan\\uninstall.exe\" /S /inner" ascii //weight: 1
        $x_1_8 = {64 65 6c 20 2f 71 20 2f 73 20 2f 66 20 25 73 79 73 74 65 6d 64 72 69 76 65 25 5c ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 5c 42 61 69 64 75 20 53 65 63 75 72 69 74 79 5c 50 43 20 46 61 73 74 65 72 5c 2a 2e 2a}  //weight: 1, accuracy: Low
        $x_1_9 = {73 65 74 20 64 61 74 61 64 69 72 3d 25 73 79 73 74 65 6d 64 72 69 76 65 25 5c ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 5c 61 76 69 72 61}  //weight: 1, accuracy: Low
        $x_1_10 = "del /q /s /f \"%datadir%\"" ascii //weight: 1
        $x_1_11 = "rem /////////////////////////////////////////////////////////////////////////PA-b2edecompile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

