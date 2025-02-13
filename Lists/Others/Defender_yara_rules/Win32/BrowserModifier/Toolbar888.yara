rule BrowserModifier_Win32_Toolbar888_17381_0
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Toolbar888"
        threat_id = "17381"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Toolbar888"
        severity = "19"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "{C1B4DEC2-2623-438e-9CA2-C9043AB28508}" ascii //weight: 10
        $x_10_2 = "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Bar888" ascii //weight: 10
        $x_3_3 = "Bar888.dll" ascii //weight: 3
        $x_3_4 = "and click YES to continue uninstallation." ascii //weight: 3
        $x_1_5 = "Uninstallation aborted." ascii //weight: 1
        $x_1_6 = "SystemBiosDate" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_3_*))) or
            (all of ($x*))
        )
}

