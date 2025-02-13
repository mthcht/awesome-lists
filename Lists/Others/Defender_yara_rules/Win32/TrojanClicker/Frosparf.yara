rule TrojanClicker_Win32_Frosparf_A_2147686797_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:Win32/Frosparf.A"
        threat_id = "2147686797"
        type = "TrojanClicker"
        platform = "Win32: Windows 32-bit platform"
        family = "Frosparf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_8_1 = "fapcf001.sytes.net" wide //weight: 8
        $x_4_2 = "ersion.vinacf.com/fapcf.html" wide //weight: 4
        $x_4_3 = "FAPCF BOT 2\\Project1.vbp" wide //weight: 4
        $x_4_4 = "FAPCF MODZ 2.1\\Project1.vbp" wide //weight: 4
        $x_1_5 = "+ CROSSFIRE TOOL +" wide //weight: 1
        $x_1_6 = "225,224,7843,227,7841,259,7855,7857" wide //weight: 1
        $x_1_7 = "ZOMBOZ V 2.1 by MEND" ascii //weight: 1
        $x_1_8 = "FAPCF TOOL\\" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_4_*) and 2 of ($x_1_*))) or
            ((1 of ($x_8_*) and 1 of ($x_4_*) and 2 of ($x_1_*))) or
            ((1 of ($x_8_*) and 2 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule TrojanClicker_Win32_Frosparf_C_2147689351_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:Win32/Frosparf.C"
        threat_id = "2147689351"
        type = "TrojanClicker"
        platform = "Win32: Windows 32-bit platform"
        family = "Frosparf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Project1" wide //weight: 1
        $x_1_2 = "BKHN" wide //weight: 1
        $x_1_3 = "anti.exe" wide //weight: 1
        $x_1_4 = "linkbucks." wide //weight: 1
        $x_1_5 = "225,224,7843,227,7841,259,7855,7857" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanClicker_Win32_Frosparf_D_2147691423_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:Win32/Frosparf.D"
        threat_id = "2147691423"
        type = "TrojanClicker"
        platform = "Win32: Windows 32-bit platform"
        family = "Frosparf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "http://adf.ly/uRBCR" wide //weight: 4
        $x_2_2 = "//game.lienminhgame.net/p/cf7.html" wide //weight: 2
        $x_1_3 = "online.html" wide //weight: 1
        $x_1_4 = "VNCFModz" wide //weight: 1
        $x_1_5 = "Patcher_CF2" wide //weight: 1
        $x_1_6 = "\\Hack CF\\" wide //weight: 1
        $x_1_7 = "\\FapCFLIB.dll" wide //weight: 1
        $x_1_8 = "kichhoathack.html" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 6 of ($x_1_*))) or
            ((1 of ($x_4_*) and 4 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanClicker_Win32_Frosparf_D_2147691423_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:Win32/Frosparf.D"
        threat_id = "2147691423"
        type = "TrojanClicker"
        platform = "Win32: Windows 32-bit platform"
        family = "Frosparf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AutoClick.vbp" wide //weight: 1
        $x_1_2 = "225,224,7843,227,7841,259,7855,7857" wide //weight: 1
        $x_1_3 = "E1,E0,1EA3,E3,1EA1,E2,103,1EA5,1EA7,1EA9,1EAB,1EAD,1EAF,1EB1,1EB3,1EB5,1EB7,C1,C0" wide //weight: 1
        $x_1_4 = "adf.ly" wide //weight: 1
        $x_1_5 = "Nhap Ma Xac Nhan" wide //weight: 1
        $x_1_6 = "InetCpl.cpl,ClearMyTracksByProcess" wide //weight: 1
        $x_1_7 = ".net/p/adfly.html" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanClicker_Win32_Frosparf_E_2147695703_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:Win32/Frosparf.E"
        threat_id = "2147695703"
        type = "TrojanClicker"
        platform = "Win32: Windows 32-bit platform"
        family = "Frosparf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DblClick" ascii //weight: 1
        $x_2_2 = "checksever.html" wide //weight: 2
        $x_2_3 = "225,224,7843,227,7841,259,7855,7857" wide //weight: 2
        $x_1_4 = "E1,E0,1EA3,E3,1EA1,E2,103,1EA5,1EA7,1EA9,1EAB,1EAD,1EAF,1EB1,1EB3,1EB5,1EB7,C1,C0" wide //weight: 1
        $x_2_5 = "CROSSFIRE TOOL" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanClicker_Win32_Frosparf_F_2147696627_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:Win32/Frosparf.F"
        threat_id = "2147696627"
        type = "TrojanClicker"
        platform = "Win32: Windows 32-bit platform"
        family = "Frosparf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "adf.ly/ad/locked" wide //weight: 2
        $x_2_2 = "225,224,7843,227,7841,259,7855,7857" wide //weight: 2
        $x_1_3 = "CROSSFIRE TOOL" wide //weight: 1
        $x_1_4 = "InetCpl.cpl,ClearMyTracksByProcess" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanClicker_Win32_Frosparf_G_2147696758_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:Win32/Frosparf.G"
        threat_id = "2147696758"
        type = "TrojanClicker"
        platform = "Win32: Windows 32-bit platform"
        family = "Frosparf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DblClick" ascii //weight: 1
        $x_1_2 = "adf.ly" wide //weight: 1
        $x_1_3 = "225,224,7843,227,7841,259,7855,7857" wide //weight: 1
        $x_1_4 = "E1,E0,1EA3,E3,1EA1,E2,103,1EA5,1EA7,1EA9,1EAB,1EAD,1EAF,1EB1,1EB3,1EB5,1EB7,C1,C0" wide //weight: 1
        $x_1_5 = "patcher_cf2.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

