rule TrojanClicker_Win32_Webin_A_2147642277_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:Win32/Webin.A"
        threat_id = "2147642277"
        type = "TrojanClicker"
        platform = "Win32: Windows 32-bit platform"
        family = "Webin"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "{871C5380-42A0-1069-A2EA-08002B30309D}" ascii //weight: 2
        $x_2_2 = "ravmond.exe" ascii //weight: 2
        $x_2_3 = "360tray.exe" ascii //weight: 2
        $x_1_4 = "\\Internet Explorer\\New Windows" ascii //weight: 1
        $x_1_5 = "PopupMgr True" ascii //weight: 1
        $x_1_6 = "\\WebNew.ini" ascii //weight: 1
        $x_1_7 = "\\Web.ini" ascii //weight: 1
        $x_1_8 = {00 63 79 69 6b 79 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_9 = "&hardid=" ascii //weight: 1
        $x_1_10 = "&netid=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 6 of ($x_1_*))) or
            ((3 of ($x_2_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

