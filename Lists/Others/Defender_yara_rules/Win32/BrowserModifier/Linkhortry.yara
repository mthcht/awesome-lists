rule BrowserModifier_Win32_Linkhortry_234930_0
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Linkhortry"
        threat_id = "234930"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Linkhortry"
        severity = "Low"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "/c \"start %s\"" ascii //weight: 2
        $x_2_2 = "refgdfbfghjuyujk" ascii //weight: 2
        $x_1_3 = {64 68 65 65 63 64 6c 64 6f 6b 67 64 73 73 00 00 78 6c 6c 6c 72 69 66 6b 67 67 73 64 6f 65 00 00}  //weight: 1, accuracy: High
        $x_1_4 = "-stapp -stapp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

