rule BrowserModifier_Win32_Suchspur_17670_0
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Suchspur"
        threat_id = "17670"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Suchspur"
        severity = "3"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "Suchspur.dll" ascii //weight: 3
        $x_3_2 = "WebPrefix" ascii //weight: 3
        $x_3_3 = "!ADWARE_SFX!" ascii //weight: 3
        $x_1_4 = "%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X" ascii //weight: 1
        $x_1_5 = "1hp=steudf/ar" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

