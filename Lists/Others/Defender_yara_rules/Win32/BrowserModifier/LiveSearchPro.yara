rule BrowserModifier_Win32_LiveSearchPro_149283_0
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/LiveSearchPro"
        threat_id = "149283"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "LiveSearchPro"
        severity = "6"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "LiveSearchPro Ver." ascii //weight: 1
        $x_1_2 = "{4D5025F3-F3DA-4300-B598-D45D37ADA74C}" ascii //weight: 1
        $x_1_3 = "offimate.com http://auto.livesearchpro.com/response" ascii //weight: 1
        $x_1_4 = "activebrz.exe" ascii //weight: 1
        $x_2_5 = {46 61 62 6f 75 74 3a 62 6c 61 6e 6b 00 68 74 74 70 3a 00 00 00 66 69 6c 65 3a 00 00 00 4c 49 56 45 53 45 41 52 43 48 50 52 4f 54 4f 4f 4c 42 41 52}  //weight: 2, accuracy: High
        $x_1_6 = "LiveSearchPro.DLL" ascii //weight: 1
        $x_2_7 = {4c 69 76 65 53 65 61 72 63 68 50 72 6f 00 00 00 53 6f 66 74 77 61 72 65 5c 4b 52 41 53 50}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

