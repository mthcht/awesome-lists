rule BrowserModifier_Win32_Cometsystems_14852_0
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Cometsystems"
        threat_id = "14852"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Cometsystems"
        severity = "233"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Comet Cursor 3.0 Installer" ascii //weight: 2
        $x_1_2 = "Software\\Microsoft\\Internet Explorer\\Search" ascii //weight: 1
        $x_3_3 = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Browser Helper Objects\\{1678F7E1-C422-11D0-AD7D-00400515CAAA}" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule BrowserModifier_Win32_Cometsystems_14852_1
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Cometsystems"
        threat_id = "14852"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Cometsystems"
        severity = "233"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "OriginalAutoSearch" wide //weight: 2
        $x_3_2 = "TOOLBAR_POPUP_BLOCKER_NUMBER_OF_BLOCKED" ascii //weight: 3
        $x_3_3 = "OriginalSearchAssistant" wide //weight: 3
        $x_3_4 = "Use Search Asst" wide //weight: 3
        $x_5_5 = "SearchRover.DLL" ascii //weight: 5
        $x_16_6 = "<IMG alt=\"Click here to disable for the remainder of the browser session\" border=\"0\" height=\"14\" id=\"travelSnooze\" width=\"42\">" ascii //weight: 16
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 3 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_16_*))) or
            (all of ($x*))
        )
}

