rule TrojanClicker_Win32_Toubaom_A_2147712090_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:Win32/Toubaom.A!bit"
        threat_id = "2147712090"
        type = "TrojanClicker"
        platform = "Win32: Windows 32-bit platform"
        family = "Toubaom"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "INETGET ( \"http://\" & $DOMAINURL & \"/ipost.php?a=1&u=\" & $IUSER & \"&i=\" & $IPCID & \"&p=\" &" wide //weight: 2
        $x_1_2 = "$WEB = \"http://www.baidu.com/p/q22339398/detail\"" wide //weight: 1
        $x_1_3 = "$WEB = \"http://q22339398.blog.163.com/profile/\"" wide //weight: 1
        $x_1_4 = "$ZURL = _SEARCH ( $YURL , \"70F8E(.*?)1A83U\" )" wide //weight: 1
        $x_1_5 = "INETGET ( $WEB , @TEMPDIR & \"\\ServerUrl.tmp\" , 1 , 0 )" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

