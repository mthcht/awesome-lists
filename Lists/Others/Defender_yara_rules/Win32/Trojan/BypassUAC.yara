rule Trojan_Win32_BypassUAC_BN_2147839340_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BypassUAC.BN!MTB"
        threat_id = "2147839340"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BypassUAC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "C:\\ProgramData\\AxlnstSV\\WindowsInstallationAssistant.exe" ascii //weight: 4
        $x_4_2 = "C:/ProgramData/AxlnstSV/WindowsInstallationAssistant.exe" wide //weight: 4
        $x_2_3 = "enhanced-google.com/lod/xlsrd.cpl" ascii //weight: 2
        $x_2_4 = "C:\\ProgramData\\AxlnstSV\\xlsrd.cpl" ascii //weight: 2
        $x_2_5 = "Lastsst.exe" ascii //weight: 2
        $x_2_6 = "Bill\\Bill.lnk" wide //weight: 2
        $x_1_7 = "GJdGn.cpl" ascii //weight: 1
        $x_1_8 = "GetTempPathW" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_4_*) and 3 of ($x_2_*))) or
            ((2 of ($x_4_*) and 2 of ($x_1_*))) or
            ((2 of ($x_4_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

