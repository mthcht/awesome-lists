rule Worm_Win32_Sheka_A_2147602781_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Sheka.A"
        threat_id = "2147602781"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Sheka"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "111"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "netsh firewall add allowedprogram" ascii //weight: 10
        $x_10_2 = "ShowSuperHidden" ascii //weight: 10
        $x_10_3 = "Hidden" ascii //weight: 10
        $x_10_4 = "CMD.EXE" ascii //weight: 10
        $x_10_5 = "[autorun]" ascii //weight: 10
        $x_10_6 = "UseAutoPlay=0" ascii //weight: 10
        $x_10_7 = "shellExecute=Recycled\\" ascii //weight: 10
        $x_10_8 = "shutdown -s -t 0" ascii //weight: 10
        $x_10_9 = "shutdown -r -t 0" ascii //weight: 10
        $x_10_10 = "System32\\rundll32.exe powrprof.dll,SetSuspendState" ascii //weight: 10
        $x_10_11 = "Start Page" ascii //weight: 10
        $x_10_12 = "Shell_TrayWnd" ascii //weight: 10
        $x_1_13 = "pc user disable" ascii //weight: 1
        $x_1_14 = "pc user enable" ascii //weight: 1
        $x_1_15 = "pc load" ascii //weight: 1
        $x_1_16 = "pc run" ascii //weight: 1
        $x_1_17 = "pc gourl" ascii //weight: 1
        $x_1_18 = "pc homepage" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((11 of ($x_10_*) and 1 of ($x_1_*))) or
            ((12 of ($x_10_*))) or
            (all of ($x*))
        )
}

