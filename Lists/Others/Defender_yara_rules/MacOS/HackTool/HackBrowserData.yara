rule HackTool_MacOS_HackBrowserData_B_2147972701_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MacOS/HackBrowserData.B"
        threat_id = "2147972701"
        type = "HackTool"
        platform = "MacOS: "
        family = "HackBrowserData"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "github.com/moond4rk/hackbrowserdata/" ascii //weight: 1
        $x_1_2 = ".keychain-db" ascii //weight: 1
        $x_1_3 = "(*) FROM moz_cookies" ascii //weight: 1
        $x_1_4 = "extractCreditCard" ascii //weight: 1
        $x_1_5 = "keychainbreaker" ascii //weight: 1
        $x_1_6 = "InternetPasswords" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

