rule HackTool_Win32_Defendercontrol_2147746246_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Defendercontrol"
        threat_id = "2147746246"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Defendercontrol"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Windows Defender Control" wide //weight: 1
        $x_1_2 = "www.sordum.org" wide //weight: 1
        $x_1_3 = "By BlueLife" wide //weight: 1
        $x_1_4 = "Disable Windows Defender" wide //weight: 1
        $x_1_5 = "Hide Window on Startup" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Win32_Defendercontrol_B_2147796445_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Defendercontrol.B"
        threat_id = "2147796445"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Defendercontrol"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Sordum Software" ascii //weight: 1
        $x_1_2 = "Unizeto Technologies" ascii //weight: 1
        $x_1_3 = "UPX0" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Win32_Defendercontrol_C_2147796446_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Defendercontrol.C"
        threat_id = "2147796446"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Defendercontrol"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $n_10_1 = "OneCyber" ascii //weight: -10
        $x_10_2 = "www.sordum.org" ascii //weight: 10
        $x_1_3 = "dControl.exe" ascii //weight: 1
        $x_1_4 = "dfControl.exe" ascii //weight: 1
        $x_1_5 = "AutoIt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule HackTool_Win32_Defendercontrol_D_2147798153_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Defendercontrol.D"
        threat_id = "2147798153"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Defendercontrol"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/TI " wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Win32_Defendercontrol_S_2147818787_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Defendercontrol.S"
        threat_id = "2147818787"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Defendercontrol"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "41"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "windows defender is currently active" ascii //weight: 10
        $x_10_2 = "windows defender is currently off" ascii //weight: 10
        $x_10_3 = "disabled windows defender!" ascii //weight: 10
        $x_10_4 = "failed to disable defender" ascii //weight: 10
        $x_1_5 = "servicesactive" ascii //weight: 1
        $x_1_6 = "trustedinstaller" ascii //weight: 1
        $x_1_7 = "sedebugprivilege" ascii //weight: 1
        $x_1_8 = "seimpersonateprivilege" ascii //weight: 1
        $x_1_9 = {77 69 6e 73 74 61 30 5c 64 65 66 61 75 6c 74 00 73 2d 31 2d 35 2d 31 38}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

