rule TrojanDropper_Win32_Ovdoz_A_2147611958_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Ovdoz.A"
        threat_id = "2147611958"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Ovdoz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "17"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "*\\AE:\\Dev\\Overdoz-V1\\Builder\\Overdoz.vbp" wide //weight: 10
        $x_1_2 = "\\Skin\\winmp.urf" wide //weight: 1
        $x_1_3 = "Dropper.exe" wide //weight: 1
        $x_1_4 = "28C4C820-401A-101B-A3C9-08002B2F49FB" wide //weight: 1
        $x_1_5 = "Melt:" wide //weight: 1
        $x_1_6 = "mnHeadOverdoz" ascii //weight: 1
        $x_1_7 = "FrmStartupKey" ascii //weight: 1
        $x_1_8 = "FrmWebDl" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

