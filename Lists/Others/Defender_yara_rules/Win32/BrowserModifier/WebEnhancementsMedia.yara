rule BrowserModifier_Win32_WebEnhancementsMedia_162880_0
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/WebEnhancementsMedia"
        threat_id = "162880"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "WebEnhancementsMedia"
        severity = "12"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "CC0F2900-8A5B-4D0D-9E44-10435BC40774}" ascii //weight: 1
        $x_1_2 = {66 61 63 65 72 61 6e 67 65 41 70 70 40 40 00}  //weight: 1, accuracy: High
        $x_1_3 = {66 61 63 65 72 61 67 65 2e 70 64 62 00}  //weight: 1, accuracy: High
        $x_1_4 = "d:\\Plugins for Browsers\\" ascii //weight: 1
        $x_1_5 = "webenhancements.me" wide //weight: 1
        $x_1_6 = "= s 'Web Enhancements'" ascii //weight: 1
        $x_1_7 = {75 07 c6 05 ?? ?? 03 10 01 83 7c 24 04 00 74 29 56 6a 00 6a 01}  //weight: 1, accuracy: Low
        $x_1_8 = {75 08 6a 01 ff 15 ?? ?? ?? ?? 83 7c 24 04 00 74 29 56 6a 00 6a 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule BrowserModifier_Win32_WebEnhancementsMedia_162880_1
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/WebEnhancementsMedia"
        threat_id = "162880"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "WebEnhancementsMedia"
        severity = "12"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {58 76 69 64 20 49 6e 73 74 61 6c 6c 61 74 69 6f 6e 00}  //weight: 10, accuracy: High
        $x_1_2 = {57 65 62 45 6e 68 61 6e 63 65 6d 65 6e 74 73 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_3 = {73 72 63 2e 68 6f 74 62 61 72 2e 63 6f 6d 2f 67 70 6c 2f 78 76 69 64 2f 00}  //weight: 1, accuracy: High
        $x_1_4 = {66 61 63 65 2d 72 61 67 65 2e 63 6f 6d 2f 65 75 6c 61 2e 68 74 6d 6c 00}  //weight: 1, accuracy: High
        $x_1_5 = {77 65 62 65 6e 68 61 6e 63 65 6d 65 6e 74 73 2e 6d 65 00}  //weight: 1, accuracy: High
        $x_1_6 = {63 6c 69 63 6b 63 6f 75 70 6f 6e 2e 6d 65 00}  //weight: 1, accuracy: High
        $x_1_7 = "babylon.com/eng/display.php" ascii //weight: 1
        $x_1_8 = {41 72 65 20 79 6f 75 20 73 75 72 65 20 79 6f 75 20 77 61 6e 74 20 74 6f 20 65 78 69 74 20 74 68 65 20 58 76 69 64 20 69 6e 73 74 61 6c 6c 61 74 69 6f 6e 3f 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule BrowserModifier_Win32_WebEnhancementsMedia_162880_2
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/WebEnhancementsMedia"
        threat_id = "162880"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "WebEnhancementsMedia"
        severity = "12"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "115"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {8d 41 f0 c7 84 24 24 02 00 00 ff ff ff ff 8d 48 0c 83 ca ff f0 0f c1 11 4a 85 d2 7f 0a}  //weight: 4, accuracy: High
        $x_4_2 = {8b f0 8b 44 24 08 83 c0 f0 c7 84 24 24 02 00 00 ff ff ff ff 8d 48 0c 83 ca ff f0 0f c1 11}  //weight: 4, accuracy: High
        $x_100_3 = "BrowserEnhancements.DLL" ascii //weight: 100
        $x_4_4 = ".StockBar" ascii //weight: 4
        $x_2_5 = "{04F3C4CF-8DCD-4D80-92B5-6A016E316869}" ascii //weight: 2
        $x_2_6 = "{B7A0F64A-9EA6-4FE4-9BD3-B9F0025B4930}" ascii //weight: 2
        $x_2_7 = "NoRemove 'Browser Helper Objects'" ascii //weight: 2
        $x_1_8 = "CurrentVersion\\Policies\\Explorer" wide //weight: 1
        $x_1_9 = "NoBackButton" wide //weight: 1
        $x_1_10 = "NoNetConnectDisconnect" wide //weight: 1
        $x_1_11 = "RestrictRun" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 2 of ($x_4_*) and 2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_100_*) and 2 of ($x_4_*) and 3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_100_*) and 3 of ($x_4_*) and 3 of ($x_1_*))) or
            ((1 of ($x_100_*) and 3 of ($x_4_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_100_*) and 3 of ($x_4_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

