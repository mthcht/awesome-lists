rule Worm_Win32_RJump_2147575999_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/RJump"
        threat_id = "2147575999"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "RJump"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 0d 9c 71 40 00 8b 15 a0 71 40 00 a1 a4 71 40 00 6a 05}  //weight: 1, accuracy: High
        $x_1_2 = {68 74 71 40 00 6a 00 ff d6 85 c0 74 09}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_RJump_F_2147581222_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/RJump.F"
        threat_id = "2147581222"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "RJump"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "87"
        strings_accuracy = "High"
    strings:
        $x_40_1 = "chacent.cn" ascii //weight: 40
        $x_20_2 = "RavMon.exe" ascii //weight: 20
        $x_15_3 = "hacent.cn/update.asp?ip=" ascii //weight: 15
        $x_15_4 = "C:\\WINDOWS\\SVCHOST.EXE" ascii //weight: 15
        $x_5_5 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\\Folder\\Hidden\\SHOWALL" ascii //weight: 5
        $x_5_6 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 5
        $x_1_7 = "CheckedValue" ascii //weight: 1
        $x_1_8 = "Hidden" ascii //weight: 1
        $x_1_9 = "shell\\Auto\\command" ascii //weight: 1
        $x_1_10 = "shell\\explore\\Command" ascii //weight: 1
        $x_1_11 = "AutoRun.inf" ascii //weight: 1
        $x_1_12 = "\\SVCHOST.INI" ascii //weight: 1
        $x_1_13 = "\\SVCHOST.EXE" ascii //weight: 1
        $x_1_14 = "Host:" ascii //weight: 1
        $x_1_15 = "downtask=" ascii //weight: 1
        $x_1_16 = "serial=" ascii //weight: 1
        $x_1_17 = "version=" ascii //weight: 1
        $x_1_18 = "task.EXE" ascii //weight: 1
        $x_1_19 = "\\MDM.EXE" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_40_*) and 2 of ($x_15_*) and 1 of ($x_5_*) and 12 of ($x_1_*))) or
            ((1 of ($x_40_*) and 2 of ($x_15_*) and 2 of ($x_5_*) and 7 of ($x_1_*))) or
            ((1 of ($x_40_*) and 1 of ($x_20_*) and 1 of ($x_15_*) and 12 of ($x_1_*))) or
            ((1 of ($x_40_*) and 1 of ($x_20_*) and 1 of ($x_15_*) and 1 of ($x_5_*) and 7 of ($x_1_*))) or
            ((1 of ($x_40_*) and 1 of ($x_20_*) and 1 of ($x_15_*) and 2 of ($x_5_*) and 2 of ($x_1_*))) or
            ((1 of ($x_40_*) and 1 of ($x_20_*) and 2 of ($x_15_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_RJump_J_2147593232_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/RJump.J"
        threat_id = "2147593232"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "RJump"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "110"
        strings_accuracy = "Low"
    strings:
        $x_50_1 = {12 34 56 78 02 00 00 00 00 00 00 00 ?? ?? 00 00 [0-96] 2e 65 78 65 00}  //weight: 50, accuracy: Low
        $x_10_2 = "windows_exe" ascii //weight: 10
        $x_10_3 = "PYTHONSCRIPT" ascii //weight: 10
        $x_10_4 = "<pythondll>" ascii //weight: 10
        $x_10_5 = "<zlib.pyd>" ascii //weight: 10
        $x_10_6 = "PYTHONINSPECT" ascii //weight: 10
        $x_5_7 = {05 00 00 00 73 13 00 00 00 47 65 74 57 69 6e 64 6f 77 73 44 69 72 65 63 74 6f 72 79 73 0b 00 00 00 50 6f 73 74 4d 65 73 73 61 67 65 73 0a 00 00 00 4d 6f 76 65 46 69 6c 65 45 78 73 12 00 00 00 47 65 74 53 79 73 74 65 6d 44 69 72 65 63 74 6f 72 79 73 0c 00 00 00 53 68 65 6c 6c 45 78 65 63 75 74 65 28}  //weight: 5, accuracy: High
        $x_5_8 = {75 72 6c 6f 70 65 6e 73 05 00 00 00 71 75 6f 74 65 28}  //weight: 5, accuracy: High
        $x_5_9 = {73 12 00 00 00 48 4b 45 59 5f 4c 4f 43 41 4c 5f 4d 41 43 48 49 4e 45 73 0e 00 00 00 4b 45 59 5f 41 4c 4c 5f 41 43 43 45 53 53 73 06 00 00 00 52 45 47 5f 53 5a}  //weight: 5, accuracy: High
        $x_1_10 = {63 3a 5c 52 61 76 4d 6f 6e [0-2] 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_11 = "c:\\AdobeR.exe" ascii //weight: 1
        $x_1_12 = "c:\\bittorrent.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_50_*) and 5 of ($x_10_*) and 2 of ($x_5_*))) or
            (all of ($x*))
        )
}

