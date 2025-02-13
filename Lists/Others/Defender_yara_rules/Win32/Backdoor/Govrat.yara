rule Backdoor_Win32_Govrat_A_2147709738_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Govrat.A"
        threat_id = "2147709738"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Govrat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2f 00 73 00 65 00 73 00 73 00 69 00 6f 00 6e 00 3f 00 6e 00 61 00 6d 00 65 00 3d 00 [0-32] 40 00 [0-32] 25 00 [0-8] 26 00 73 00 65 00 72 00 69 00 61 00 6c 00 3d 00}  //weight: 1, accuracy: Low
        $x_1_2 = {2f 73 65 73 73 69 6f 6e 3f 6e 61 6d 65 3d [0-32] 40 [0-32] 25 [0-8] 26 73 65 72 69 61 6c 3d}  //weight: 1, accuracy: Low
        $x_1_3 = "http://phoneupdates.xyz" ascii //weight: 1
        $x_1_4 = {2e 5c 70 69 70 65 5c [0-2] 74 65 73 74}  //weight: 1, accuracy: Low
        $x_1_5 = "com_bits.cpp" wide //weight: 1
        $x_1_6 = "unmount.bat" wide //weight: 1
        $x_1_7 = "dll-loader.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule Backdoor_Win32_Govrat_A_2147709738_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Govrat.A"
        threat_id = "2147709738"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Govrat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_8_1 = "com_bits.cpp" wide //weight: 8
        $x_8_2 = "CNotifyInterface.cpp" wide //weight: 8
        $x_8_3 = "\\\\.\\pipe\\testascxzc" ascii //weight: 8
        $x_1_4 = "File: " wide //weight: 1
        $x_1_5 = "Expression: " wide //weight: 1
        $x_1_6 = "Line: " wide //weight: 1
        $x_1_7 = "Program: " wide //weight: 1
        $x_1_8 = "StartServiceA" ascii //weight: 1
        $x_1_9 = "GetDriveType" ascii //weight: 1
        $x_1_10 = "ShellExecuteW" ascii //weight: 1
        $x_1_11 = "WinVerifyTrust" ascii //weight: 1
        $x_8_12 = "Global\\{9F040D7A-F034-4868-85A6-C20FD27CDB6B}" ascii //weight: 8
        $x_8_13 = "c:\\temp\\dll-loader.exe" wide //weight: 8
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_8_*) and 6 of ($x_1_*))) or
            ((4 of ($x_8_*))) or
            (all of ($x*))
        )
}

