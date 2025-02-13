rule Worm_Win32_Emerleox_K_2147599941_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Emerleox.K"
        threat_id = "2147599941"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Emerleox"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "310"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Ras.exe" ascii //weight: 1
        $x_1_2 = "avp.com" ascii //weight: 1
        $x_1_3 = "avp.exe" ascii //weight: 1
        $x_1_4 = "runiep.exe" ascii //weight: 1
        $x_1_5 = "PFW.exe" ascii //weight: 1
        $x_1_6 = "FYFireWall.exe" ascii //weight: 1
        $x_1_7 = "rfwmain.exe" ascii //weight: 1
        $x_1_8 = "rfwsrv.exe" ascii //weight: 1
        $x_1_9 = "KAVPF.exe" ascii //weight: 1
        $x_1_10 = "KPFW32.exe" ascii //weight: 1
        $x_1_11 = "nod32kui.exe" ascii //weight: 1
        $x_1_12 = "nod32.exe" ascii //weight: 1
        $x_1_13 = "Navapsvc.exe" ascii //weight: 1
        $x_1_14 = "Navapw32.exe" ascii //weight: 1
        $x_1_15 = "avconsol.exe" ascii //weight: 1
        $x_1_16 = "webscanx.exe" ascii //weight: 1
        $x_1_17 = "NPFMntor.exe" ascii //weight: 1
        $x_1_18 = "vsstat.exe" ascii //weight: 1
        $x_1_19 = "KPfwSvc.exe" ascii //weight: 1
        $x_1_20 = "RavTask.exe" ascii //weight: 1
        $x_1_21 = "Rav.exe" ascii //weight: 1
        $x_1_22 = "RavMon.exe" ascii //weight: 1
        $x_1_23 = "mmsk.exe" ascii //weight: 1
        $x_1_24 = "WoptiClean.exe" ascii //weight: 1
        $x_1_25 = "QQKav.exe" ascii //weight: 1
        $x_100_26 = "cmd /c echo Y| cacls" ascii //weight: 100
        $x_100_27 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 100
        $x_100_28 = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\" ascii //weight: 100
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_100_*) and 10 of ($x_1_*))) or
            (all of ($x*))
        )
}

