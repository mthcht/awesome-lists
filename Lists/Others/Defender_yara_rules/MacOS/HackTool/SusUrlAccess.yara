rule HackTool_MacOS_SusUrlAccess_A_2147775876_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MacOS/SusUrlAccess.A"
        threat_id = "2147775876"
        type = "HackTool"
        platform = "MacOS: "
        family = "SusUrlAccess"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "curl" wide //weight: 1
        $x_1_2 = "wget" wide //weight: 1
        $x_1_3 = "git" wide //weight: 1
        $x_10_4 = ".tor2web" wide //weight: 10
        $x_10_5 = ".onion" wide //weight: 10
        $x_10_6 = ".tor2socks" wide //weight: 10
        $x_10_7 = "exploit-db.com" wide //weight: 10
        $x_10_8 = "pastebin.com" wide //weight: 10
        $x_10_9 = "anonfile.com" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

