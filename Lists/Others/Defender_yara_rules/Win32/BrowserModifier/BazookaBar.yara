rule BrowserModifier_Win32_BazookaBar_3050_0
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/BazookaBar"
        threat_id = "3050"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "BazookaBar"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "usersstarArticsBar.dll" ascii //weight: 10
        $x_10_2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\BazookaBar" ascii //weight: 10
        $x_10_3 = "}\\EnablePopup" ascii //weight: 10
        $x_1_4 = "BazookaBarBand" ascii //weight: 1
        $x_1_5 = "MyArmory.com" wide //weight: 1
        $x_1_6 = "http://www.myarmory.com/search/?Keywords=" ascii //weight: 1
        $x_1_7 = "Parasiteware Detector" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*))) or
            (all of ($x*))
        )
}

