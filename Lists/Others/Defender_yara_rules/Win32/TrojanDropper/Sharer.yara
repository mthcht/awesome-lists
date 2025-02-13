rule TrojanDropper_Win32_Sharer_A_2147624532_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Sharer.A"
        threat_id = "2147624532"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Sharer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\billgates.exe" wide //weight: 1
        $x_1_2 = "iniuser1 stop Microsoftword" wide //weight: 1
        $x_1_3 = "iniuser1 stop svchost" wide //weight: 1
        $x_1_4 = "iniuser1 stop RasAuto" wide //weight: 1
        $x_1_5 = "microsoft.exe" wide //weight: 1
        $x_1_6 = "CCProxy.exe" wide //weight: 1
        $x_1_7 = "rfwmain.exe" wide //weight: 1
        $x_1_8 = "pfw.exe" wide //weight: 1
        $x_1_9 = "\\CCproxy.ini" wide //weight: 1
        $x_1_10 = "kill.bat" wide //weight: 1
        $x_1_11 = ":redel" wide //weight: 1
        $x_1_12 = "if exist " wide //weight: 1
        $x_1_13 = "goto redel" wide //weight: 1
        $x_1_14 = "del %0" wide //weight: 1
        $x_1_15 = "scan.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Sharer_B_2147624593_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Sharer.B"
        threat_id = "2147624593"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Sharer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "82"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "\\ccproxy\\" wide //weight: 10
        $x_10_2 = "\\drivers\\disdn\\1sass.exe" wide //weight: 10
        $x_10_3 = "\\drivers\\disdn\\svchost.exe" wide //weight: 10
        $x_10_4 = {2f 00 77 00 77 00 77 00 2e 00 76 00 70 00 6e 00 2d 00 76 00 70 00 6e 00 2e 00 63 00 6e 00 3a 00 [0-32] 2e 00 61 00 73 00 70 00 3f 00 4e 00 75 00 6d 00 62 00 65 00 72 00 3d 00}  //weight: 10, accuracy: Low
        $x_10_5 = {2f 00 77 00 77 00 77 00 2e 00 32 00 30 00 30 00 39 00 68 00 65 00 6c 00 6c 00 6f 00 2e 00 63 00 6e 00 3a 00 [0-32] 2e 00 61 00 73 00 70 00 3f 00 4e 00 75 00 6d 00 62 00 65 00 72 00 3d 00}  //weight: 10, accuracy: Low
        $x_10_6 = "goto redel" wide //weight: 10
        $x_10_7 = "iniuser1 stop" wide //weight: 10
        $x_1_8 = "sql stop RunAServces" wide //weight: 1
        $x_1_9 = "sql stop CCproxy" wide //weight: 1
        $x_1_10 = "sql stop svchost" wide //weight: 1
        $x_1_11 = "sql stop RasAuto" wide //weight: 1
        $x_1_12 = "sql stop wmisrvs" wide //weight: 1
        $x_1_13 = "sql stop taskmgr" wide //weight: 1
        $x_1_14 = "sql delete CCproxy" wide //weight: 1
        $x_1_15 = "sql delete svchost" wide //weight: 1
        $x_1_16 = "sql delete RasAuto" wide //weight: 1
        $x_1_17 = "sql delete wmisrvs" wide //weight: 1
        $x_1_18 = "sql delete taskmgr" wide //weight: 1
        $x_1_19 = "sql stop Bethserv" wide //weight: 1
        $x_1_20 = "sql stop Microsoftbill" wide //weight: 1
        $x_1_21 = "sql delete Bethserv" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((7 of ($x_10_*) and 12 of ($x_1_*))) or
            (all of ($x*))
        )
}

