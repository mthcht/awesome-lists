rule BrowserModifier_Win32_Foxiebro_235004_0
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Foxiebro"
        threat_id = "235004"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Foxiebro"
        severity = "3"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "/mg?alpha=" ascii //weight: 1
        $x_1_2 = "act=if&cg=" ascii //weight: 1
        $x_1_3 = "&mv=3&enc=1" ascii //weight: 1
        $x_1_4 = "QueryString = it=loud" ascii //weight: 1
        $x_1_5 = "plugin-container" ascii //weight: 1
        $x_1_6 = "{1AA60054-57D9-4F99-9A55-D0FBFBE7ECD3}" ascii //weight: 1
        $x_1_7 = "{4AA46D49-459F-4358-B4D1-169048547C23}" ascii //weight: 1
        $x_1_8 = {68 74 74 70 3a 2f 2f 69 6e 73 74 61 6c 6c 2e 30 00 2e 63 6f 6d 2f 69 68}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

