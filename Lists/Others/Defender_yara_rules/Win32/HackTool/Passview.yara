rule HackTool_Win32_Passview_2147597639_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Passview"
        threat_id = "2147597639"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Passview"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "11111.exe" ascii //weight: 2
        $x_2_2 = "fj4ghga23_fsa.txt" ascii //weight: 2
        $x_2_3 = "hhiuew33.com/" ascii //weight: 2
        $x_2_4 = "\\Release\\ResourceVerCur.pdb" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule HackTool_Win32_Passview_A_2147694232_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Passview.A!dha"
        threat_id = "2147694232"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Passview"
        severity = "High"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "100"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Protected Storage PassView" ascii //weight: 1
        $x_1_2 = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows Messaging Subsystem\\Profiles" ascii //weight: 1
        $x_1_3 = "Software\\Microsoft\\Office\\Outlook\\OMI Account Manager\\Accounts" ascii //weight: 1
        $x_1_4 = "ms ie ftp Passwords" ascii //weight: 1
        $x_1_5 = "inetcomm server passwords" ascii //weight: 1
        $x_1_6 = "Software\\Microsoft\\Internet Explorer\\IntelliForms\\SPW" ascii //weight: 1
        $x_1_7 = "5e7e8100-9138-11d1-945a-00c04fc308ff" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Win32_Passview_AMTB_2147938643_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Passview!AMTB"
        threat_id = "2147938643"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Passview"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "usb_ftppasswd_x" ascii //weight: 1
        $x_1_2 = "ppp%d_password" ascii //weight: 1
        $x_1_3 = "w11g_wepkey0" ascii //weight: 1
        $x_1_4 = "RouterPassView.exe" ascii //weight: 1
        $x_1_5 = "super_passwd" ascii //weight: 1
        $n_100_6 = "Uninst.exe" ascii //weight: -100
        $n_100_7 = "Uninstaller.exe" ascii //weight: -100
        $n_100_8 = "Uninstal.exe" ascii //weight: -100
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

