rule BrowserModifier_Win32_SearcherSmart_133055_0
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/SearcherSmart"
        threat_id = "133055"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "SearcherSmart"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "searchersmart search enhancer" wide //weight: 2
        $x_2_2 = "searchersmart sidebar" wide //weight: 2
        $x_2_3 = "searchersmart logic" wide //weight: 2
        $x_1_4 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Browser Helper Objects\\%s" wide //weight: 1
        $x_1_5 = "SOFTWARE\\Microsoft\\Internet Explorer\\Explorer Bars\\%s" wide //weight: 1
        $x_1_6 = "CLSID\\%s\\Implemented Categories\\{00021493-0000-0000-C000-000000000046}" wide //weight: 1
        $x_1_7 = "/install.php" wide //weight: 1
        $x_1_8 = "/notify.php" wide //weight: 1
        $x_1_9 = "/getopt.php" wide //weight: 1
        $x_2_10 = "/rdr.php" wide //weight: 2
        $x_2_11 = "myss_install_mutex" wide //weight: 2
        $x_2_12 = "myss_getopt_mutex" wide //weight: 2
        $x_1_13 = "_settings" wide //weight: 1
        $x_1_14 = "Search panel" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_2_*) and 7 of ($x_1_*))) or
            ((5 of ($x_2_*) and 5 of ($x_1_*))) or
            ((6 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

