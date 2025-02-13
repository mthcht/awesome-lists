rule BrowserModifier_Win64_Shafmia_365261_0
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win64/Shafmia"
        threat_id = "365261"
        type = "BrowserModifier"
        platform = "Win64: Windows 64-bit platform"
        family = "Shafmia"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MicroApp\\reg.bat" wide //weight: 1
        $x_1_2 = "edge.bat" wide //weight: 1
        $x_1_3 = "apps-helper" wide //weight: 1
        $x_1_4 = "set edge_ext" ascii //weight: 1
        $x_1_5 = "%edge%\\ExtensionInstallForcelist\" /v \"6\" /t REG_SZ /d %id% /f" ascii //weight: 1
        $x_1_6 = "EdgeInstall.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule BrowserModifier_Win64_Shafmia_365261_1
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win64/Shafmia"
        threat_id = "365261"
        type = "BrowserModifier"
        platform = "Win64: Windows 64-bit platform"
        family = "Shafmia"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "chrome.bat" wide //weight: 1
        $x_1_2 = "apps-helper" wide //weight: 1
        $x_1_3 = "set chrome_ext" ascii //weight: 1
        $x_1_4 = "set file=%helper%\\apps.crx" ascii //weight: 1
        $x_1_5 = "%chrome%\\ExtensionInstallForcelist\" /v \"6\" /t REG_SZ /d %id% /f" ascii //weight: 1
        $x_1_6 = "REG DELETE %base32%\\%chrome%\\Extensions\\%id% /f" ascii //weight: 1
        $x_1_7 = "set helper=%LocalAppdata%\\ServiceApp\\apps-helper" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

