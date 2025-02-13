rule Backdoor_Win32_Sapphire_SA_2147750692_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Sapphire.SA!MSR"
        threat_id = "2147750692"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Sapphire"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "31"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "*.sur" wide //weight: 10
        $x_10_2 = "*.uwt" wide //weight: 10
        $x_10_3 = "*.tvs" wide //weight: 10
        $x_10_4 = "uc09_bwkhal.iha" wide //weight: 10
        $x_10_5 = "wernf21_dymjcn.kjc" wide //weight: 10
        $x_10_6 = "vd10_cxlibm.jib" wide //weight: 10
        $x_5_7 = "%LOCALAPPDATA%\\" wide //weight: 5
        $x_5_8 = "%TEMP%\\" wide //weight: 5
        $x_1_9 = "_nextafter" ascii //weight: 1
        $x_1_10 = "Startup" wide //weight: 1
        $x_1_11 = "Internet Explorer" wide //weight: 1
        $x_1_12 = "Chrome" wide //weight: 1
        $x_1_13 = "Safari" wide //weight: 1
        $x_1_14 = ">----------" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 6 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*))) or
            ((4 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Sapphire_SB_2147750693_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Sapphire.SB!MSR"
        threat_id = "2147750693"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Sapphire"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "wernf21_dymjcn.kjc" wide //weight: 1
        $x_1_2 = "%TEMP%\\..\\" wide //weight: 1
        $x_1_3 = "LnkDll.dll" ascii //weight: 1
        $x_1_4 = ".uwt" wide //weight: 1
        $x_1_5 = "Nview32 ApiSet Lib" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

