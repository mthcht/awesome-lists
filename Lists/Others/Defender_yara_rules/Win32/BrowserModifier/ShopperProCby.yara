rule BrowserModifier_Win32_ShopperProCby_208154_0
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/ShopperProCby"
        threat_id = "208154"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "ShopperProCby"
        severity = "6"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "[SbTracer::" wide //weight: 3
        $x_3_2 = "IEInstaller::CloseBrowser - Closed %d processes" wide //weight: 3
        $x_5_3 = "Microsoft\\Internet Explorer\\ApprovedExtensionsMigration" wide //weight: 5
        $x_5_4 = "ChromeInstaller::EnableExtensionUnpack - Extension is successfully enabled" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 2 of ($x_3_*))) or
            ((2 of ($x_5_*) and 1 of ($x_3_*))) or
            (all of ($x*))
        )
}

