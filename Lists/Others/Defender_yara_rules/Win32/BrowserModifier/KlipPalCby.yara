rule BrowserModifier_Win32_KlipPalCby_208229_0
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/KlipPalCby"
        threat_id = "208229"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "KlipPalCby"
        severity = "Low"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Updater_OfSvc_BrowserSettings_2" wide //weight: 1
        $x_1_2 = {4f 00 46 00 53 00 5f 00 ?? ?? 67 00 73 00 69 00 3f 00 63 00 69 00 64 00 3d 00 7b 00 30 00 7d 00 26 00 69 00 73 00 3d 00 7b 00 31 00 7d 00}  //weight: 1, accuracy: Low
        $x_1_3 = {6b 00 6d 00 73 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 ?? ?? 69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 65 00 72 00 41 00 72 00 67 00 75 00 6d 00 65 00 6e 00 74 00 73 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule BrowserModifier_Win32_KlipPalCby_208229_1
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/KlipPalCby"
        threat_id = "208229"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "KlipPalCby"
        severity = "Low"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "IE 11 fix - Starting fix & OptimizeEnablePlugin is true" ascii //weight: 10
        $x_10_2 = "Wrote IE Auto Enable IgnoreFrameApprovalCheck" ascii //weight: 10
        $x_1_3 = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Ext" ascii //weight: 1
        $x_1_4 = "IgnoreFrameApprovalCheck" ascii //weight: 1
        $x_1_5 = "Software\\Microsoft\\Internet Explorer\\ApprovedExtensionsMigration" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

