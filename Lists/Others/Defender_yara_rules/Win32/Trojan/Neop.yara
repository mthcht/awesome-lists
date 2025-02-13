rule Trojan_Win32_Neop_2147624665_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neop!gmb"
        threat_id = "2147624665"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neop"
        severity = "Critical"
        info = "gmb: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "reg add HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa /v forceguest /t REG_DWORD /d 0 /f" ascii //weight: 1
        $x_1_2 = "net user iusr_debug" ascii //weight: 1
        $x_1_3 = "net localgroup administrators iusr_debug /add" ascii //weight: 1
        $x_1_4 = "net accounts /maxpwage:unlimited" ascii //weight: 1
        $x_1_5 = "running..." wide //weight: 1
        $x_1_6 = "ntlog.bat" wide //weight: 1
        $x_1_7 = "folderbind.dll" wide //weight: 1
        $x_1_8 = "filebinddoc.dll" wide //weight: 1
        $x_1_9 = "commandcmd.dll" wide //weight: 1
        $x_1_10 = "ntdetect.bat" wide //weight: 1
        $x_1_11 = "CMD.exe /C ntdetect.bat %s >.\\Result" wide //weight: 1
        $x_1_12 = "Program Files\\Common Files\\System\\wab32.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

