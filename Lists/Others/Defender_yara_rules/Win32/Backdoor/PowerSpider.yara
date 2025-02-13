rule Backdoor_Win32_PowerSpider_N_2147595480_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/PowerSpider.gen!N"
        threat_id = "2147595480"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "PowerSpider"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "285"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "jokycard.exe" ascii //weight: 100
        $x_100_2 = "oicq2000.cfg" ascii //weight: 100
        $x_10_3 = "smtp.%s" ascii //weight: 10
        $x_10_4 = "WNetEnumCachedPasswords" ascii //weight: 10
        $x_10_5 = "Shell DocObject View" ascii //weight: 10
        $x_10_6 = "RedMoon" ascii //weight: 10
        $x_10_7 = "Ctrl+Alt+End" ascii //weight: 10
        $x_10_8 = "URLDownloadToFileA" ascii //weight: 10
        $x_10_9 = "CPwdView" ascii //weight: 10
        $x_10_10 = "CSecondPage" ascii //weight: 10
        $x_5_11 = "%s\\pwdbox*.exe" ascii //weight: 5
        $x_5_12 = "c:\\Program Files\\Tencent" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_100_*) and 8 of ($x_10_*) and 1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_PowerSpider_N_2147603613_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/PowerSpider.N"
        threat_id = "2147603613"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "PowerSpider"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "merrychristmas" ascii //weight: 1
        $x_1_2 = "/myrunner_up.exe" ascii //weight: 1
        $x_1_3 = "SOFTWARE\\Classes\\MSipy" ascii //weight: 1
        $x_1_4 = "%s\\~~~08d%02d%d.tmp" ascii //weight: 1
        $x_1_5 = "PASS %s" ascii //weight: 1
        $x_1_6 = "\\mspbhook.dll" ascii //weight: 1
        $x_1_7 = "_exe." ascii //weight: 1
        $x_1_8 = "aha01%" ascii //weight: 1
        $x_1_9 = "power001.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (8 of ($x*))
}

rule Backdoor_Win32_PowerSpider_C_2147649674_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/PowerSpider.C"
        threat_id = "2147649674"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "PowerSpider"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6c 6f 63 61 6c 69 70 3d [0-7] 64 6e 73 33 3d}  //weight: 1, accuracy: Low
        $x_1_2 = "%s\\scanre*.exe" ascii //weight: 1
        $x_1_3 = "Internet Explorer_Server" ascii //weight: 1
        $x_1_4 = "ScreenSave_Data" ascii //weight: 1
        $x_1_5 = {52 65 64 4d 6f 6f 6e 0d 0a 00}  //weight: 1, accuracy: High
        $x_1_6 = {50 61 73 73 77 6f 72 64 32 [0-5] 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 41 63 63 6f 75 6e 74 20 4d 61 6e 61 67 65 72 5c 41 63 63 6f 75 6e 74 73 5c 25 30 38 64 [0-5] 5c 61 70 70 5c 45 6e 74 65 72 4e 65 74 2e 69 6e 69}  //weight: 1, accuracy: Low
        $x_1_7 = {2e 6d 61 69 6c 2e 79 61 68 6f 6f 2e 63 6f 6d 00 73 6d 74 70 2e 25 73}  //weight: 1, accuracy: High
        $x_1_8 = "?ScanPwd" ascii //weight: 1
        $x_1_9 = {61 68 61 25 64 6f 6b 6f 6b 00}  //weight: 1, accuracy: High
        $x_1_10 = {53 4f 46 54 57 41 52 45 5c 43 6c 61 73 73 65 73 5c 53 75 6e 6e 79 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (8 of ($x*))
}

