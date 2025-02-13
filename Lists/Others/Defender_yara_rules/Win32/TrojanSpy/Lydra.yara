rule TrojanSpy_Win32_Lydra_AC_2147592973_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Lydra.AC"
        threat_id = "2147592973"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Lydra"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "94"
        strings_accuracy = "High"
    strings:
        $x_30_1 = "{2ADF5-4756-4481-578E-7875458858900}" ascii //weight: 30
        $x_20_2 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 20
        $x_10_3 = "killself" ascii //weight: 10
        $x_10_4 = "Roshal.WinRAR.WinRAR" ascii //weight: 10
        $x_10_5 = "silent.txt" ascii //weight: 10
        $x_5_6 = "winsys" ascii //weight: 5
        $x_5_7 = "msorcvp" ascii //weight: 5
        $x_3_8 = "CreateSemaphoreA" ascii //weight: 3
        $x_3_9 = "StartServiceCtrlDispatcherA" ascii //weight: 3
        $x_3_10 = "Toolhelp32ReadProcessMemory" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_30_*) and 1 of ($x_20_*) and 3 of ($x_10_*) and 1 of ($x_5_*) and 3 of ($x_3_*))) or
            ((1 of ($x_30_*) and 1 of ($x_20_*) and 3 of ($x_10_*) and 2 of ($x_5_*) and 2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Lydra_A_2147593044_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Lydra.gen!A"
        threat_id = "2147593044"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Lydra"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "80"
        strings_accuracy = "High"
    strings:
        $x_50_1 = "{2ADF5-4756-4481-578E-7875458858900}" wide //weight: 50
        $x_10_2 = "SOFTWARE\\Microsoft\\Windows Messaging Subsystem" ascii //weight: 10
        $x_10_3 = "MAPISendMail" ascii //weight: 10
        $x_10_4 = "Roshal.WinRAR.WinRAR" ascii //weight: 10
        $x_10_5 = "UnmapViewOfFile" ascii //weight: 10
        $x_10_6 = "smtp.mail.ru" ascii //weight: 10
        $x_10_7 = "if exist %1 goto" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_50_*) and 3 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Lydra_B_2147593045_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Lydra.gen!B"
        threat_id = "2147593045"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Lydra"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "80"
        strings_accuracy = "High"
    strings:
        $x_50_1 = "{65D5AFFB-D4EF-49AA-GFFG-5DA5E12E300A}" ascii //weight: 50
        $x_10_2 = "SOFTWARE\\Microsoft\\Windows Messaging Subsystem" ascii //weight: 10
        $x_10_3 = "MAPISendMail" ascii //weight: 10
        $x_10_4 = "Roshal.WinRAR.WinRAR" ascii //weight: 10
        $x_10_5 = "UnmapViewOfFile" ascii //weight: 10
        $x_10_6 = "smtp.mail.ru" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_50_*) and 3 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Lydra_C_2147594471_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Lydra.gen!C"
        threat_id = "2147594471"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Lydra"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "35"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 10
        $x_10_2 = "FPUMaskValue" ascii //weight: 10
        $x_10_3 = "UnhookWindowsHookEx" ascii //weight: 10
        $x_3_4 = {69 65 63 6f 6d 6e 2e 64 6c 6c 00 00 00 00 57 69 6e 5f 50 72 6f 63 00}  //weight: 3, accuracy: High
        $x_3_5 = {69 65 63 6f 6d 6e 2e 64 6c 6c 00 00 00 00 47 65 74 41 6e 64 53 65 74 00}  //weight: 3, accuracy: High
        $x_2_6 = {76 69 61 75 64 2e 64 6c 6c 00 42 65 67 69 6e 57 69 6e 50 72 6f 63 00}  //weight: 2, accuracy: High
        $x_2_7 = {76 69 61 75 64 2e 64 6c 6c 00 53 74 61 72 74 49 6e 74 72 75 64 69 6e 67 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((3 of ($x_10_*) and 2 of ($x_3_*))) or
            (all of ($x*))
        )
}

