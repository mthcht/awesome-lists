rule BrowserModifier_Win32_Spesseo_236327_0
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Spesseo"
        threat_id = "236327"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Spesseo"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Software\\SpecialSearchOffer" ascii //weight: 1
        $x_1_2 = {5c 53 65 63 75 72 65 20 50 72 65 66 65 72 65 6e 63 65 73 00}  //weight: 1, accuracy: High
        $x_1_3 = {61 63 6f 6e ?? ?? ?? 66 74 77 61 ?? ?? ?? 5c 42 4c 42 ?? ?? ?? 68 72 6f 6d ?? ?? ?? ?? 53 6f ?? ?? ?? 65 ?? ?? ?? ?? 6f 6f ?? ?? ?? 67 ?? ?? ?? 65}  //weight: 1, accuracy: Low
        $x_2_4 = {50 6a 00 6a 00 6a 1c 6a 00 ff 15 ?? ?? ?? ?? 68 04 01 00 00 8d 85 ?? ?? ?? ?? 6a 00 50 e8 ?? ?? ?? ?? 83 c4 ?? c7 85 ?? ?? ?? ?? ?? ?? ?? ?? 8d 8d ?? ?? ?? ?? c7 85 ?? ?? ?? ?? 00 00 00 00 c6 85 ?? ?? ?? ?? 00 6a 18 68}  //weight: 2, accuracy: Low
        $x_2_5 = {50 6a 00 6a 00 6a 1c 6a 00 ff 15 ?? ?? ?? ?? 68 03 01 00 00 8d 44 24 ?? 6a 00 50 c6 44 24 ?? 00 e8 ?? ?? ?? ?? 83 c4 ?? 8d 4c 24 ?? 6a 18 68}  //weight: 2, accuracy: Low
        $x_2_6 = "campaignID=%s&geo=%s&source=%%s&userID=%s&osVersion=%s&browserVersion=%s&instVersion=%s&sessID=%s" ascii //weight: 2
        $x_1_7 = "ssoprovide.com/so.php?test=" ascii //weight: 1
        $x_1_8 = "insthrm.com/?" ascii //weight: 1
        $x_1_9 = "values ('%d','BrowserSafer','BrowserSafer','Installer Technology','')" ascii //weight: 1
        $x_1_10 = "values ('%d','BrowserSafer','BrowserSafer','Company','')" ascii //weight: 1
        $x_2_11 = {74 69 76 65 66 c7 85 ?? ?? ?? ?? 74 77 66 c7 85 ?? ?? ?? ?? 47 6f 66 c7 85 ?? ?? ?? ?? 70 65 c7 85 ?? ?? ?? ?? 6d 65 5c 4e 66 c7 85 ?? ?? ?? ?? 68 2e}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

