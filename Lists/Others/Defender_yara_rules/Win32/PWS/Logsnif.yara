rule PWS_Win32_Logsnif_B_2147583505_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Logsnif.gen!B"
        threat_id = "2147583505"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Logsnif"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "http://www.norton-kaspersky.com/trf/tools" ascii //weight: 10
        $x_1_2 = "\\Outlook Express\\wab.exe" ascii //weight: 1
        $x_1_3 = "Software\\Microsoft\\Direct3DX" ascii //weight: 1
        $x_1_4 = "CreateProcessW" ascii //weight: 1
        $x_1_5 = "NtCreateSection" ascii //weight: 1
        $x_1_6 = "ProgramFiles" ascii //weight: 1
        $x_1_7 = "ProgramFiles" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Logsnif_C_2147583506_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Logsnif.gen!C"
        threat_id = "2147583506"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Logsnif"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "166"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "--__abcd-xyz789__--" ascii //weight: 100
        $x_5_2 = "svchost.exe" ascii //weight: 5
        $x_5_3 = "explorer.exe" ascii //weight: 5
        $x_5_4 = "FFGrabber" ascii //weight: 5
        $x_5_5 = "IEFaker" ascii //weight: 5
        $x_5_6 = "IEGrabber" ascii //weight: 5
        $x_5_7 = "IEMod" ascii //weight: 5
        $x_5_8 = "PSGrabber" ascii //weight: 5
        $x_10_9 = "GetModInfo" ascii //weight: 10
        $x_10_10 = "Execute" ascii //weight: 10
        $x_10_11 = "Activate" ascii //weight: 10
        $x_1_12 = "Connection: Close" ascii //weight: 1
        $x_1_13 = "Content-Disposition: form-data; name=" ascii //weight: 1
        $x_1_14 = "Content-Length: %d" ascii //weight: 1
        $x_1_15 = "Content-Type: multipart/form-data; boundary=%s" ascii //weight: 1
        $x_1_16 = "shell\\open\\command" ascii //weight: 1
        $x_1_17 = "CertGrabber" ascii //weight: 1
        $x_1_18 = "NtCreateSection" ascii //weight: 1
        $x_1_19 = "ZwMapViewOfSection" ascii //weight: 1
        $x_1_20 = "ReadProcessMemory" ascii //weight: 1
        $x_1_21 = "WriteProcessMemory" ascii //weight: 1
        $x_1_22 = "SOFTWARE\\Clients\\StartMenuInternet" ascii //weight: 1
        $x_1_23 = "%ProgramFiles%\\Outlook Express\\wab.exe" ascii //weight: 1
        $x_1_24 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\SharedTaskScheduler" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 2 of ($x_10_*) and 7 of ($x_5_*) and 11 of ($x_1_*))) or
            ((1 of ($x_100_*) and 3 of ($x_10_*) and 5 of ($x_5_*) and 11 of ($x_1_*))) or
            ((1 of ($x_100_*) and 3 of ($x_10_*) and 6 of ($x_5_*) and 6 of ($x_1_*))) or
            ((1 of ($x_100_*) and 3 of ($x_10_*) and 7 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Logsnif_D_2147597299_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Logsnif.gen!D"
        threat_id = "2147597299"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Logsnif"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "140"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "--__abcd-xyz789__--" ascii //weight: 100
        $x_10_2 = {49 45 4d 6f 64 00 00 00 5c 79 61 74 6f 6f 6c 2e 64 6c 6c 00 00 00 00 00 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 42 72 6f 77 73 65 72 20 48 65 6c 70 65 72 20 4f 62 6a 65 63 74 73}  //weight: 10, accuracy: High
        $x_10_3 = {4d 54 42 61 73 65 00 ff 5c 6d 74 5f 33 32 2e 64 6c 6c 00 00 5c 74 61 73 6b 6d 61 6e 67 2e 65 78 65}  //weight: 10, accuracy: High
        $x_10_4 = {41 63 74 69 76 61 74 65 00 44 65 6c 65 74 65 00 47 65 74 4d 6f 64 49 6e 66 6f 00 49 6e 73 74 61 6c 6c 00 53 74 6f 70}  //weight: 10, accuracy: High
        $x_10_5 = {49 6e 69 74 69 61 6c 69 7a 65 00 00 69 65 78 70 6c 6f 72 65 2e 65 78 65 00 00 00 00 50 4f 53 54 00 00 00 00 43 6f 6e 74 65 6e 74 2d 54 79 70 65 3a 20 6d 75 6c 74 69 70 61 72 74 2f 66 6f 72 6d 2d 64 61 74 61 3b 20 62 6f 75 6e 64 61 72 79 3d 25 73 00 00 25 73 3f 25 30 38 78 00 2d 2d 25 73 2d 2d 0d 0a}  //weight: 10, accuracy: High
        $x_10_6 = {59 41 2e 54 30 30 4c 42 41 52 00 00 59 61 68 6f 6f 20 54 6f 6f 6c 62 61 72 00 00 00 7b 35 34 43 37 44 31 44 44 2d 34 32 39 36 2d 34 35 31 65 2d 42 37 35 36 2d 31 45 39 34 46 36 36 35 42 34 46 46 7d}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 4 of ($x_10_*))) or
            (all of ($x*))
        )
}

