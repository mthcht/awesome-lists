rule TrojanDownloader_PowerShell_sLoad_A_2147730026_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:PowerShell/sLoad.A"
        threat_id = "2147730026"
        type = "TrojanDownloader"
        platform = "PowerShell: "
        family = "sLoad"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "40"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "schtasks" wide //weight: 10
        $x_10_2 = "apprunLog" wide //weight: 10
        $x_10_3 = ".vbs" wide //weight: 10
        $x_10_4 = "1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_PowerShell_sLoad_A_2147730026_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:PowerShell/sLoad.A"
        threat_id = "2147730026"
        type = "TrojanDownloader"
        platform = "PowerShell: "
        family = "sLoad"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "80"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "bitsadmin" wide //weight: 10
        $x_10_2 = "transfer" wide //weight: 10
        $x_10_3 = "download" wide //weight: 10
        $x_10_4 = "captcha.php" wide //weight: 10
        $x_10_5 = "&v=microsoft windows" wide //weight: 10
        $x_10_6 = "*svchost*svchost*svchost*svchost*svchost" wide //weight: 10
        $x_10_7 = "*wininit*winlogon*" wide //weight: 10
        $x_10_8 = "&cpu=" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

