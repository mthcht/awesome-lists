rule BrowserModifier_Win32_Elopesmut_225275_0
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Elopesmut"
        threat_id = "225275"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Elopesmut"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "--app=%swindow-promo.html" wide //weight: 2
        $x_2_2 = "gaaghkhghnijpedknoihgelfibidjccn" wide //weight: 2
        $x_1_3 = "Chrome_WidgetWin_1" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule BrowserModifier_Win32_Elopesmut_225275_1
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Elopesmut"
        threat_id = "225275"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Elopesmut"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Emotiplus WebInstaller" wide //weight: 10
        $x_10_2 = {43 00 6f 00 6d 00 70 00 61 00 6e 00 79 00 4e 00 61 00 6d 00 65 00 00 00 00 00 44 00 65 00 76 00 65 00 6c 00 6f 00 70 00 6d 00 65 00 6e 00 74 00 20 00 4d 00 65 00 64 00 69 00 61 00 20 00 37 00 33 00}  //weight: 10, accuracy: High
        $x_2_3 = "/window-promo.com/condition-g" wide //weight: 2
        $x_1_4 = "\\Internet Explorer\\Approved Extensions" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

