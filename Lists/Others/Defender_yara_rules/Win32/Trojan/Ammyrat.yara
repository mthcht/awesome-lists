rule Trojan_Win32_Ammyrat_C_2147735437_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ammyrat.C"
        threat_id = "2147735437"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ammyrat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Global\\Ammyy.Service.FinishEvent" wide //weight: 1
        $x_1_2 = "WinSta0\\Winlogon" wide //weight: 1
        $x_1_3 = "\\\\.\\Pipe\\TerminalServer\\SystemExecSrvr\\%d" wide //weight: 1
        $x_1_4 = "AmmyyAdminTarget3" wide //weight: 1
        $x_1_5 = "ammyy.dmp" wide //weight: 1
        $x_1_6 = "Ammyy_fake_wnd" wide //weight: 1
        $x_1_7 = "\\taskmgr.exe" wide //weight: 1
        $x_1_8 = "\\ammyygeneric\\target\\TrFmFileSys.h" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

