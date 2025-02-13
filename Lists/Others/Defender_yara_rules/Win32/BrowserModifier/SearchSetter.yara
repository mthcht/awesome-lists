rule BrowserModifier_Win32_SearchSetter_223441_0
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/SearchSetter"
        threat_id = "223441"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "SearchSetter"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "www-searching.com/?pid=s&s=" ascii //weight: 10
        $x_10_2 = "SetterExe.exe" wide //weight: 10
        $x_1_3 = "chrome://settings-frame/#syi518" ascii //weight: 1
        $x_1_4 = {50 00 52 00 45 00 56 00 53 00 45 00 41 00 52 00 43 00 48 00 49 00 45 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {49 00 45 00 53 00 45 00 54 00 00 00}  //weight: 1, accuracy: High
        $x_1_6 = "Running on VMWare" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 4 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

