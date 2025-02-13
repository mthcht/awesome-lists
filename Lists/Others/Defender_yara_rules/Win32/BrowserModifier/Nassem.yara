rule BrowserModifier_Win32_Nassem_139056_0
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Nassem"
        threat_id = "139056"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Nassem"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "DoBHOEvent" ascii //weight: 3
        $x_3_2 = {2e 44 4c 4c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77}  //weight: 3, accuracy: High
        $x_1_3 = "CONFIGURATOR_GLOBAL_LOCK" wide //weight: 1
        $x_1_4 = "MAXFeedURL" wide //weight: 1
        $x_2_5 = "messangerupdate.net/conf" wide //weight: 2
        $x_2_6 = "\\Drivers\\pub.dll" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_3_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

