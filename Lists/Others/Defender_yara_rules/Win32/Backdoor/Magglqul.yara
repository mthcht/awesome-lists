rule Backdoor_Win32_Magglqul_A_2147832908_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Magglqul.A!dha"
        threat_id = "2147832908"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Magglqul"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Select *From Win32_UserAccount Where LocalAccount = True" wide //weight: 1
        $x_1_2 = "It's Blocking I/O" ascii //weight: 1
        $x_1_3 = "SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp" ascii //weight: 1
        $x_1_4 = "ElevateTS User Password Port" ascii //weight: 1
        $x_1_5 = "The Account %s Has Been Cloned To %s" ascii //weight: 1
        $x_1_6 = "exec master.dbo.sp_addlogin %s,%s;exec master.dbo.sp_addsrvrolemember %s,sysadmin" ascii //weight: 1
        $x_1_7 = "HostList [Port] UserList PassList Thread" ascii //weight: 1
        $x_1_8 = "SqlScan" ascii //weight: 1
        $x_1_9 = "RShell" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule Backdoor_Win32_Magglqul_C_2147832922_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Magglqul.C!dha"
        threat_id = "2147832922"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Magglqul"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MSSMBios_RawSMBiosTables" wide //weight: 1
        $x_1_2 = "DetourTransactionCommit Failure On %s" ascii //weight: 1
        $x_1_3 = "Account Owner Not Found For The SID" ascii //weight: 1
        $x_2_4 = "maggie" ascii //weight: 2
        $x_1_5 = "Mozilla/4.0 (compatible)" ascii //weight: 1
        $x_1_6 = "SMBiosData" ascii //weight: 1
        $x_1_7 = "Create Download Thread Successfully" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

