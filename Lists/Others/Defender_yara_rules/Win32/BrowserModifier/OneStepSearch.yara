rule BrowserModifier_Win32_OneStepSearch_18033_0
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/OneStepSearch"
        threat_id = "18033"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "OneStepSearch"
        severity = "7"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {00 4f 6e 65 53 74 65 70 20 53 65 61 72 63 68 20 6c 6f 61 64 65 72 00}  //weight: 10, accuracy: High
        $x_10_2 = {00 4f 6e 65 53 74 65 70 53 65 61 72 63 68 2e 6e 65 74 2c 20 49 6e 63 2e 00}  //weight: 10, accuracy: High
        $x_3_3 = "Copyright (c) 2007 OneStepSearch.net, Inc." ascii //weight: 3
        $x_3_4 = {49 00 6e 00 74 00 65 00 72 00 6e 00 61 00 6c 00 4e 00 61 00 6d 00 65 00 00 00 6f 00 6e 00 65 00 73 00 74 00 65 00 70 00}  //weight: 3, accuracy: High
        $x_3_5 = {4f 00 72 00 69 00 67 00 69 00 6e 00 61 00 6c 00 46 00 69 00 6c 00 65 00 6e 00 61 00 6d 00 65 00 00 00 6f 00 6e 00 65 00 73 00 74 00 65 00 70 00 2e 00 65 00 78 00 65 00}  //weight: 3, accuracy: High
        $x_2_6 = "GetProcAddress" ascii //weight: 2
        $x_2_7 = "GetCommandLineA" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 2 of ($x_3_*) and 2 of ($x_2_*))) or
            ((2 of ($x_10_*) and 3 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule BrowserModifier_Win32_OneStepSearch_18033_1
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/OneStepSearch"
        threat_id = "18033"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "OneStepSearch"
        severity = "7"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "33"
        strings_accuracy = "High"
    strings:
        $x_7_1 = {77 77 77 2e 6f 6e 65 73 74 65 70 73 65 61 72 63 68 2e 6e 65 74 00 00 00 00 53 63 72 69 70 74 00 00 68 6f 6d 65 2e 6a 73}  //weight: 7, accuracy: High
        $x_7_2 = "onestepsearch.net/?prt=%s&" ascii //weight: 7
        $x_7_3 = {4f 6e 65 53 74 65 70 20 53 65 61 72 63 68 00 00 7b 35 42 34 43 33 42 34 33 2d 34 39 42 36 2d 34 32 41 37 2d 41 36 30 32 2d 46 37 41 43 44 43 41 30 44 34 30 39 7d}  //weight: 7, accuracy: High
        $x_7_4 = {44 6c 6c 50 61 74 68 00 6f 6e 65 73 74 65 70 2e 65 78 65}  //weight: 7, accuracy: High
        $x_7_5 = {4f 6e 65 53 74 65 70 53 65 61 72 63 68 00 00 00 54 65 6d 70 49 6e 73 74 61 6c 6c 44 69 72}  //weight: 7, accuracy: High
        $x_7_6 = {55 6e 69 6e 73 74 61 6c 6c 5c 4f 6e 65 53 74 65 70 53 65 61 72 63 68 00 00 00 54 65 73 74 48 6f 73 74}  //weight: 7, accuracy: High
        $x_6_7 = "OneStepSearch_deleted_" ascii //weight: 6
        $x_6_8 = "http://upgrade.onestepsearch.net" ascii //weight: 6
        $x_6_9 = "OneStep Search Options Panel" ascii //weight: 6
        $x_6_10 = "Update and control for OneStep Search" ascii //weight: 6
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_7_*) and 4 of ($x_6_*))) or
            ((3 of ($x_7_*) and 2 of ($x_6_*))) or
            ((4 of ($x_7_*) and 1 of ($x_6_*))) or
            ((5 of ($x_7_*))) or
            (all of ($x*))
        )
}

rule BrowserModifier_Win32_OneStepSearch_18033_2
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/OneStepSearch"
        threat_id = "18033"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "OneStepSearch"
        severity = "7"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "51"
        strings_accuracy = "Low"
    strings:
        $x_50_1 = {c0 e0 02 8b d5 c1 fa 04 0a d0}  //weight: 50, accuracy: High
        $x_5_2 = {63 68 65 63 6b 75 70 64 [0-4] 73 6c 6f 61 64 [0-4] 74 62 68 69 64 65 [0-4] 74 62 73 68 6f 77}  //weight: 5, accuracy: Low
        $x_1_3 = {4f 6e 65 53 74 65 70 53 65 61 72 63 68 2e 2e 2e 00}  //weight: 1, accuracy: High
        $x_1_4 = {4f 6e 65 53 74 65 70 2e 2e 2e 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_50_*) and 1 of ($x_1_*))) or
            ((1 of ($x_50_*) and 1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule BrowserModifier_Win32_OneStepSearch_18033_3
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/OneStepSearch"
        threat_id = "18033"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "OneStepSearch"
        severity = "7"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {40 00 ff 75 0c 50 e8 4e ff ff ff 0b c0 75 07 bb 01 00 00 00 eb 34 83 c0 08 89 45 f8 2b 45 fc 83 7d 10 00 74 03 83 e8 08 3d 00 08 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {25 ff ff 00 00 bb 69 90 00 00 f7 e3 8b 1d ?? ?? 40 00 c1 eb 10 03 c3 a3 ?? ?? 40 00 a1 ?? ?? 40 00 25 ff ff 00 00 bb 69 90 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule BrowserModifier_Win32_OneStepSearch_18033_4
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/OneStepSearch"
        threat_id = "18033"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "OneStepSearch"
        severity = "7"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {63 68 65 63 6b 75 70 64 [0-4] 73 6c 6f 61 64 [0-4] 74 62 68 69 64 65 [0-4] 74 62 73 68 6f 77}  //weight: 5, accuracy: Low
        $x_1_2 = {53 00 65 00 61 00 72 00 63 00 68 00 49 00 6e 00 4f 00 6e 00 65 00 53 00 74 00 65 00 70 00 2e 00 2e 00 2e 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {53 00 65 00 61 00 72 00 63 00 68 00 49 00 6e 00 4f 00 6e 00 65 00 53 00 74 00 65 00 70 00 20 00 4f 00 70 00 74 00 69 00 6f 00 6e 00 73 00 20 00 50 00 61 00 6e 00 65 00 6c 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {53 00 65 00 61 00 72 00 63 00 68 00 49 00 6e 00 4f 00 6e 00 65 00 53 00 74 00 65 00 70 00 20 00 53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 20 00 41 00 63 00 74 00 69 00 76 00 61 00 74 00 65 00 64 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule BrowserModifier_Win32_OneStepSearch_B_127825_0
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/OneStepSearch.B"
        threat_id = "127825"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "OneStepSearch"
        severity = "10"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "{1FBA04EE-3024-11D2-8F1F-0000F87ABD16}" ascii //weight: 10
        $x_10_2 = {61 75 63 74 69 6f 6e 00 61 75 6b 74 69 6f 6e 00 62 6f 6f 6b 00 62 6f 75 74 69 71 75 65 00 63 61 6c 6c 00 63 68 61 74}  //weight: 10, accuracy: High
        $x_1_3 = "Path=Profiles/foo" ascii //weight: 1
        $x_1_4 = "?prt=%s&keywords={searchTerms}" ascii //weight: 1
        $x_1_5 = "chrome\\chrome.rdf" ascii //weight: 1
        $x_1_6 = "ShowToolbarButton" ascii //weight: 1
        $x_1_7 = {43 6f 6d 6d 61 6e 64 00 49 6e 73 74 61 6c 6c 00 4d 61 69 6e 00 53 65 72 76 69 63 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule BrowserModifier_Win32_OneStepSearch_B_127825_1
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/OneStepSearch.B"
        threat_id = "127825"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "OneStepSearch"
        severity = "10"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "32"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "\\Internet Explorer\\SearchScopes" ascii //weight: 10
        $x_10_2 = "{1FBA04EE-3024-11D2-8F1F-0000F87ABD16}" ascii //weight: 10
        $x_10_3 = {61 75 63 74 69 6f 6e 00 61 75 6b 74 69 6f 6e 00 62 6f 6f 6b 00 62 6f 75 74 69 71 75 65 00 63 61 6c 6c 00 63 68 61 74}  //weight: 10, accuracy: High
        $x_1_4 = "Path=Profiles/foo" ascii //weight: 1
        $x_1_5 = "?prt=%s&keywords={searchTerms}" ascii //weight: 1
        $x_1_6 = "chrome\\chrome.rdf" ascii //weight: 1
        $x_1_7 = "ShowToolbarButton" ascii //weight: 1
        $x_1_8 = {43 6f 6d 6d 61 6e 64 00 49 6e 73 74 61 6c 6c 00 4d 61 69 6e 00 53 65 72 76 69 63 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule BrowserModifier_Win32_OneStepSearch_C_134931_0
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/OneStepSearch.C"
        threat_id = "134931"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "OneStepSearch"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "32"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "www.seekeen.com" ascii //weight: 10
        $x_10_2 = "{1FBA04EE-3024-11D2-8F1F-0000F87ABD16}" ascii //weight: 10
        $x_10_3 = {61 75 63 74 69 6f 6e 00 61 75 6b 74 69 6f 6e 00 62 6f 6f 6b 00 62 6f 75 74 69 71 75 65 00 63 61 6c 6c 00 63 68 61 74}  //weight: 10, accuracy: High
        $x_1_4 = "Path=Profiles/foo" ascii //weight: 1
        $x_1_5 = "?prt=%s&keywords={searchTerms}" ascii //weight: 1
        $x_1_6 = "chrome\\chrome.rdf" ascii //weight: 1
        $x_1_7 = "ShowToolbarButton" ascii //weight: 1
        $x_1_8 = {43 6f 6d 6d 61 6e 64 00 49 6e 73 74 61 6c 6c 00 4d 61 69 6e 00 53 65 72 76 69 63 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

