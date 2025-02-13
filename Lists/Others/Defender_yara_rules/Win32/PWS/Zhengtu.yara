rule PWS_Win32_Zhengtu_A_2147600027_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Zhengtu.A!dll"
        threat_id = "2147600027"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Zhengtu"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "31"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "zhengtu" ascii //weight: 10
        $x_10_2 = {06 00 00 00 26 55 73 65 72 3d 00 00 ff ff ff ff 06 00 00 00 26 50 61 73 73 3d 00 00 ff ff ff ff 08 00 00 00 26 53 65 72 76 65 72 3d}  //weight: 10, accuracy: High
        $x_5_3 = {08 00 00 00 26 50 43 4e 61 6d 65 3d 00 00 00 00 ff ff ff ff 0b 00 00 00 26 50 43 45 64 69 74 69 6f 6e 3d 00 ff ff ff ff 07 00 00 00 53 65 6e 64 20 4f 4b}  //weight: 5, accuracy: High
        $x_5_4 = {09 00 00 00 26 57 69 6e 4e 61 6d 65 3d 00 00 00 ff ff ff ff 0b 00 00 00 26 57 69 6e 42 61 6e 42 65 6e 3d 00 ff ff ff ff 07 00 00 00 53 65 6e 64 20 4f 4b}  //weight: 5, accuracy: High
        $x_1_5 = "Content-Type: application/x-www-form-urlencoded" ascii //weight: 1
        $x_1_6 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 1
        $x_1_7 = {5f 44 4c 4c 2e 64 6c 6c [0-6] 48 6f 6f 6b}  //weight: 1, accuracy: Low
        $x_1_8 = "CallNextHookEx" ascii //weight: 1
        $x_1_9 = "GetKeyboardType" ascii //weight: 1
        $x_1_10 = "WriteFile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 6 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Zhengtu_B_2147641869_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Zhengtu.B!dll"
        threat_id = "2147641869"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Zhengtu"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {c6 02 e9 6a 04 68 00 30 00 00 8b 4b 18 83 c1 05 51 6a 00 ff 15}  //weight: 2, accuracy: High
        $x_1_2 = "%s\\data\\fmodex.dll1" ascii //weight: 1
        $x_1_3 = "zhengtu2.dat" ascii //weight: 1
        $x_1_4 = "patchupdate.exe" ascii //weight: 1
        $x_1_5 = "360tray.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Zhengtu_B_2147650735_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Zhengtu.B"
        threat_id = "2147650735"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Zhengtu"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 44 24 44 8b 4c 24 30 83 c4 18 8d 54 24 14 c6 44 24 10 4d c6 44 24 11 5a}  //weight: 1, accuracy: High
        $x_1_2 = "cmd /c rundll32.exe %s St %s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

