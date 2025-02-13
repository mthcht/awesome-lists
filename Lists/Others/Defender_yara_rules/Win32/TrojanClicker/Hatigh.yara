rule TrojanClicker_Win32_Hatigh_A_2147611261_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:Win32/Hatigh.A"
        threat_id = "2147611261"
        type = "TrojanClicker"
        platform = "Win32: Windows 32-bit platform"
        family = "Hatigh"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Software\\Microsoft\\Internet Explorer\\Main" ascii //weight: 1
        $x_1_2 = "7search.com/scripts/security/validate.asp" ascii //weight: 1
        $x_1_3 = "Software\\Microsoft\\Internet Explorer\\New Windows" ascii //weight: 1
        $x_1_4 = "grdsfsd.bat" ascii //weight: 1
        $x_1_5 = "value=no_spyware" ascii //weight: 1
        $x_2_6 = "http://66.199.179.8/search.php" ascii //weight: 2
        $x_2_7 = "66.250.74.152/kw_img/img_gen.php" ascii //weight: 2
        $x_1_8 = ":$:*:1:::B:I:T:Z:`:j:p:v:" ascii //weight: 1
        $x_1_9 = "http://tripborn.org/rd/rep2.php?er[0]=5.1-" ascii //weight: 1
        $x_1_10 = "http://firstwolf.org/rd/rep.php?er[0]=5.1-" ascii //weight: 1
        $x_1_11 = "if exist %1 goto gl234sh" ascii //weight: 1
        $x_1_12 = "PopupMgr" ascii //weight: 1
        $x_1_13 = "Suurch" ascii //weight: 1
        $x_1_14 = "findnseek" ascii //weight: 1
        $x_1_15 = "shopzil" ascii //weight: 1
        $x_1_16 = "www.suurch.com" ascii //weight: 1
        $x_1_17 = "testovaya hren" ascii //weight: 1
        $x_1_18 = "fraud" ascii //weight: 1
        $x_1_19 = "NookupPrivilegeValueA" ascii //weight: 1
        $x_1_20 = "QpenProcessToken" ascii //weight: 1
        $x_1_21 = "TegCloseKey" ascii //weight: 1
        $x_1_22 = "TegSetValueExA" ascii //weight: 1
        $x_1_23 = "JttpSendRequestA" ascii //weight: 1
        $x_1_24 = "JttpOpenRequestA" ascii //weight: 1
        $x_1_25 = "WRLDownloadToFileA" ascii //weight: 1
        $x_1_26 = "UhellExecuteA" ascii //weight: 1
        $x_1_27 = "cheat" ascii //weight: 1
        $x_1_28 = "vimg.php?" ascii //weight: 1
        $x_1_29 = "BCMSVCRT.DLL" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((20 of ($x_1_*))) or
            ((1 of ($x_2_*) and 18 of ($x_1_*))) or
            ((2 of ($x_2_*) and 16 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanClicker_Win32_Hatigh_B_2147611262_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:Win32/Hatigh.B"
        threat_id = "2147611262"
        type = "TrojanClicker"
        platform = "Win32: Windows 32-bit platform"
        family = "Hatigh"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Software\\Microsoft\\Internet Explorer\\Main" ascii //weight: 1
        $x_1_2 = "7search.com/scripts/security/validate.asp" ascii //weight: 1
        $x_1_3 = "Software\\Microsoft\\Internet Explorer\\New Windows" ascii //weight: 1
        $x_1_4 = "grdsfsd.bat" ascii //weight: 1
        $x_1_5 = "value=no_spyware" ascii //weight: 1
        $x_1_6 = "http://66.199.179.8/search.php" ascii //weight: 1
        $x_1_7 = "66.250.74.152/kw_img/img_gen.php" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule TrojanClicker_Win32_Hatigh_C_2147611263_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:Win32/Hatigh.C"
        threat_id = "2147611263"
        type = "TrojanClicker"
        platform = "Win32: Windows 32-bit platform"
        family = "Hatigh"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {81 38 68 69 64 64 75 ?? (68 ?? ?? ?? ?? 68 ?? ?? ?? ?? e8 ?? ??|ff 75 f0 e8 ?? ?? 00 00 c7 45 ec 00 00 00 00 eb ?? ff)}  //weight: 10, accuracy: Low
        $x_1_2 = {eb 05 22 25 73 22 00 68}  //weight: 1, accuracy: High
        $x_1_3 = "value=no_spyware" ascii //weight: 1
        $x_1_4 = "/kw_img/img_gen.php" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

