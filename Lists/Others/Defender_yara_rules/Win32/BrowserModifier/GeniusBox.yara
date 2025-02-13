rule BrowserModifier_Win32_GeniusBox_223731_0
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/GeniusBox"
        threat_id = "223731"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "GeniusBox"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://www.maxwebsearch.com/s?i_" wide //weight: 1
        $x_1_2 = "GeniusBox Enhanced Search" wide //weight: 1
        $x_1_3 = "CONFIG_KEY_SET_HOME_PAGE" ascii //weight: 1
        $x_1_4 = "C:\\Projects\\Extensions\\BHO\\Install\\Release\\gb_ex_install.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

