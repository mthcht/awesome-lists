rule TrojanClicker_Win32_NightClick_A_2147716175_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:Win32/NightClick.A"
        threat_id = "2147716175"
        type = "TrojanClicker"
        platform = "Win32: Windows 32-bit platform"
        family = "NightClick"
        severity = "60"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "\\oas\\Upd\\Release\\winstagetask.pdb" ascii //weight: 2
        $x_2_2 = "DeskWinStage" wide //weight: 2
        $x_1_3 = "MyApp1.0" wide //weight: 1
        $x_2_4 = "%s\\WinStage\\%s" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanClicker_Win32_NightClick_A_2147716175_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:Win32/NightClick.A"
        threat_id = "2147716175"
        type = "TrojanClicker"
        platform = "Win32: Windows 32-bit platform"
        family = "NightClick"
        severity = "60"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "111"
        strings_accuracy = "High"
    strings:
        $x_100_1 = ":\\work\\oas\\" ascii //weight: 100
        $x_10_2 = "partnerid2=%d%d" wide //weight: 10
        $x_10_3 = "uid=uid" wide //weight: 10
        $x_1_4 = "click to coord - x:%d && y:%d" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((1 of ($x_100_*) and 2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule TrojanClicker_Win32_NightClick_A_2147716175_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:Win32/NightClick.A"
        threat_id = "2147716175"
        type = "TrojanClicker"
        platform = "Win32: Windows 32-bit platform"
        family = "NightClick"
        severity = "60"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "version=%s&uid=%s&sid=%s&subid=%s" wide //weight: 1
        $x_1_2 = "rangesoft.org/files/update.exe" wide //weight: 1
        $x_1_3 = "\\work\\oas\\updService\\Release\\updservice.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanClicker_Win32_NightClick_A_2147716175_3
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:Win32/NightClick.A"
        threat_id = "2147716175"
        type = "TrojanClicker"
        platform = "Win32: Windows 32-bit platform"
        family = "NightClick"
        severity = "60"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/%s/campaignid/2/userid/%s/siteid/%s/version/%s" wide //weight: 1
        $x_1_2 = "E:\\work\\oas\\cef" ascii //weight: 1
        $x_1_3 = "| p2.y:%d| p1.x:%d | p1.y:%d" wide //weight: 1
        $x_1_4 = "debug_page_zykrom=%d;" wide //weight: 1
        $x_1_5 = ".proceedcheck.xyz" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanClicker_Win32_NightClick_A_2147716175_4
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:Win32/NightClick.A"
        threat_id = "2147716175"
        type = "TrojanClicker"
        platform = "Win32: Windows 32-bit platform"
        family = "NightClick"
        severity = "60"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_10_1 = ":\\work\\oas\\" ascii //weight: 10
        $x_1_2 = "data.oas-service.com/param/" wide //weight: 1
        $x_1_3 = "data.rangesoft.org/param/" wide //weight: 1
        $x_1_4 = "data.solscanner.com/param/" wide //weight: 1
        $x_1_5 = "stats.onlineadscanner.com" wide //weight: 1
        $x_10_6 = "/%s/campaignid/2/userid/%s/siteid/%s/version/%s" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

