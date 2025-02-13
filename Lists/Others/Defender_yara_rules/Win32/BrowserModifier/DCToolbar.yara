rule BrowserModifier_Win32_DCToolbar_17970_0
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/DCToolbar"
        threat_id = "17970"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "DCToolbar"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "toolbar_sample.dll" ascii //weight: 1
        $x_1_2 = "rundll32.exe advpack.dll,DelNodeRunDLL32 \"" ascii //weight: 1
        $x_3_3 = "{5F1ABCDB-A875-46c1-8345-" ascii //weight: 3
        $x_1_4 = "Make Default Toolbar" ascii //weight: 1
        $x_1_5 = ">`#document - document" ascii //weight: 1
        $x_1_6 = "Error processing XML file: " ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

