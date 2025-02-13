rule TrojanClicker_Win32_Clickelkite_A_2147663280_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:Win32/Clickelkite.A"
        threat_id = "2147663280"
        type = "TrojanClicker"
        platform = "Win32: Windows 32-bit platform"
        family = "Clickelkite"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "linklog.ilikeclick.com" ascii //weight: 5
        $x_5_2 = "IlikeClick.dat" ascii //weight: 5
        $x_5_3 = "&ilc_cusVar1=&target_url=" ascii //weight: 5
        $x_5_4 = "/directAppUpdate/" ascii //weight: 5
        $x_1_5 = "ToolbarRestore.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

