rule Backdoor_Win32_Hostsrv_A_2147641803_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Hostsrv.A"
        threat_id = "2147641803"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Hostsrv"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%WINDIR%\\system32\\drivers\\etc\\hosts" ascii //weight: 1
        $x_2_2 = "Usage: srv32.exe -[start|stop|install|unins" ascii //weight: 2
        $x_1_3 = "Server: FuckYou" ascii //weight: 1
        $x_1_4 = "taskkill /f /im" ascii //weight: 1
        $x_1_5 = "ipconfig /flushdns" ascii //weight: 1
        $x_1_6 = "taskmgr.exe,regedit.exe,rstrui.exe,msconfig.exe,avz.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

