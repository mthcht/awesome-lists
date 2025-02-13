rule BrowserModifier_Win32_Xider_235408_0
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Xider"
        threat_id = "235408"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Xider"
        severity = "Mid"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Ext\\CLSID" ascii //weight: 1
        $x_1_2 = "Software\\Microsoft\\Internet Explorer\\ApprovedExtensionsMigration" ascii //weight: 1
        $x_2_3 = "crieenabler" ascii //weight: 2
        $x_2_4 = "IeEnabler.exe" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule BrowserModifier_Win32_Xider_235408_1
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Xider"
        threat_id = "235408"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Xider"
        severity = "Mid"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "34"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Ext\\CLSID" ascii //weight: 10
        $x_10_2 = "Software\\Microsoft\\Internet Explorer\\Approved Extensions" ascii //weight: 10
        $x_10_3 = {00 65 6e 61 62 6c 65 5f 62 68 6f 00}  //weight: 10, accuracy: High
        $x_2_4 = "crieenabler" ascii //weight: 2
        $x_2_5 = "IEExtensionUtils" ascii //weight: 2
        $x_2_6 = "IeEnabler.exe" ascii //weight: 2
        $x_2_7 = "Already approved this bho in the past" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule BrowserModifier_Win32_Xider_235408_2
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Xider"
        threat_id = "235408"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Xider"
        severity = "Mid"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "26"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Ext\\PreApproved" ascii //weight: 10
        $x_10_2 = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Ext\\CLSID" ascii //weight: 10
        $x_1_3 = {65 72 72 5f 75 6e 6d 69 78 69 6e 67 5f 69 65 5f 65 6e 61 62 6c 65 72 5f [0-9] 43 6f 70 79 69 6e 67 20 66 72 6f 6d [0-9] 5c [0-15] 2e 74 6d 70}  //weight: 1, accuracy: Low
        $x_1_4 = {65 72 72 5f 65 78 74 72 61 74 69 6e 67 5f 69 65 5f 65 6e 61 62 6c 65 72 a0 00 5c [0-8] 2d [0-4] 2d [0-4] 2d [0-4] 2d [0-12] 2d 32 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_5_5 = {2f 6d 6f 6e 65 74 69 7a 61 74 69 6f 6e 2e 67 69 66 3f 65 76 65 6e 74 3d [0-2] 26 69 62 69 63 3d ?? ?? ?? 26 76 65 72 69 66 69 65 72 3d ?? ?? ?? 26 63 61 6d 70 61 69 67 6e 3d}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

