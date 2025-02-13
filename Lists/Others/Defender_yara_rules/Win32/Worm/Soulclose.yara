rule Worm_Win32_Soulclose_A_2147608225_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Soulclose.A"
        threat_id = "2147608225"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Soulclose"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "230"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "OpenYourSoul" wide //weight: 100
        $x_10_2 = " goto gm" wide //weight: 10
        $x_10_3 = " goto kill" wide //weight: 10
        $x_10_4 = "kill.bat" wide //weight: 10
        $x_10_5 = ":kill" wide //weight: 10
        $x_10_6 = " goto redel" wide //weight: 10
        $x_10_7 = "open=cf.exe" wide //weight: 10
        $x_10_8 = ":redel" wide //weight: 10
        $x_10_9 = "OnD=a" ascii //weight: 10
        $x_10_10 = "cf.exe" wide //weight: 10
        $x_10_11 = ".exe.exe" wide //weight: 10
        $x_5_12 = "%.0YJ%" ascii //weight: 5
        $x_5_13 = "llF\\%i.Q" ascii //weight: 5
        $x_5_14 = "del %0" wide //weight: 5
        $x_5_15 = "vmmreg32.exe" wide //weight: 5
        $x_1_16 = "[AutoRun]" wide //weight: 1
        $x_1_17 = "if exist " wide //weight: 1
        $x_1_18 = "autorun.inf" wide //weight: 1
        $x_2_19 = "avp.exe" wide //weight: 2
        $x_2_20 = "1.vbp" wide //weight: 2
        $x_1_21 = "GetTempPathA" ascii //weight: 1
        $x_2_22 = "A*\\AC:\\Documents and Settings\\" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Soulclose_B_2147610695_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Soulclose.B"
        threat_id = "2147610695"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Soulclose"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "OpenYourSoul" wide //weight: 1
        $x_1_2 = "kill.bat" wide //weight: 1
        $x_1_3 = {63 00 66 00 2e 00 65 00 78 00 65 00 [0-18] 61 00 75 00 74 00 6f 00 72 00 75 00 6e 00 2e 00 69 00 6e 00 66 00 [0-18] 5b 00 41 00 75 00 74 00 6f 00 52 00 75 00 6e 00 5d 00 [0-18] 6f 00 70 00 65 00 6e 00 3d 00 63 00 66 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

