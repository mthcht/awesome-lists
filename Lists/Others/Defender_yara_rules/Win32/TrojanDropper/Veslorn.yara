rule TrojanDropper_Win32_Veslorn_B_2147603180_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Veslorn.B"
        threat_id = "2147603180"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Veslorn"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "605"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {50 68 c8 00 00 00 8b 85 ?? ff ff ff 8b 4d ?? 8d 04 81 50 ff 75 ac e8 ?? ?? ff ff 89 85 ?? ff ff ff}  //weight: 100, accuracy: Low
        $x_100_2 = "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options" wide //weight: 100
        $x_100_3 = "Wscript.Shell" wide //weight: 100
        $x_100_4 = "if exist" wide //weight: 100
        $x_100_5 = "OpenProcess" ascii //weight: 100
        $x_100_6 = "EnumProcessModules" ascii //weight: 100
        $x_1_7 = "360safe.exe" wide //weight: 1
        $x_1_8 = "360tray.exe" wide //weight: 1
        $x_1_9 = "UpdaterUI.exe" wide //weight: 1
        $x_1_10 = "avp.exe" wide //weight: 1
        $x_1_11 = "Mcshield.exe" wide //weight: 1
        $x_1_12 = "VsTskMgr.exe" wide //weight: 1
        $x_1_13 = "naPrdMgr.exe" wide //weight: 1
        $x_1_14 = "TBMon.exe" wide //weight: 1
        $x_1_15 = "scan32.exe" wide //weight: 1
        $x_1_16 = "CCenter.exe" wide //weight: 1
        $x_1_17 = "RavTask.exe" wide //weight: 1
        $x_1_18 = "Rav.exe" wide //weight: 1
        $x_1_19 = "RavMon.exe" wide //weight: 1
        $x_1_20 = "RavmonD.exe" wide //weight: 1
        $x_1_21 = "RavStub.exe" wide //weight: 1
        $x_1_22 = "kvsrvxp.exe" wide //weight: 1
        $x_1_23 = "KRegEx.exe" wide //weight: 1
        $x_1_24 = "kavsvc.exe" wide //weight: 1
        $x_1_25 = "UIHost.exe" wide //weight: 1
        $x_1_26 = "TrojDie.exe" wide //weight: 1
        $x_1_27 = "FrogAgent.exe" wide //weight: 1
        $x_1_28 = "kav32.exe" wide //weight: 1
        $x_1_29 = "kavstart.exe" wide //weight: 1
        $x_1_30 = "katmain.exe" wide //weight: 1
        $x_1_31 = "kpfwsvc.exe" wide //weight: 1
        $x_1_32 = "kpfw32.exe" wide //weight: 1
        $x_1_33 = "rfwmain.exe" wide //weight: 1
        $x_1_34 = "rfwproxy.exe" wide //weight: 1
        $x_1_35 = "rfwsrv.exe" wide //weight: 1
        $x_1_36 = "Taskmgr.exe" wide //weight: 1
        $x_1_37 = "Regedit.exe" wide //weight: 1
        $x_1_38 = "Msconfig.exe" wide //weight: 1
        $x_1_39 = "icesword.exe" wide //weight: 1
        $x_1_40 = "KWatch.exe" wide //weight: 1
        $x_1_41 = "SnipeSword.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_100_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

