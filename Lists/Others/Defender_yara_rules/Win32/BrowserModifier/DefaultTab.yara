rule BrowserModifier_Win32_DefaultTab_207033_0
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/DefaultTab"
        threat_id = "207033"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "DefaultTab"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "DefaultTabSearch" ascii //weight: 1
        $x_1_2 = "api.defaulttab.com/toolbar/open" ascii //weight: 1
        $x_1_3 = {53 6f 66 74 77 61 72 65 5c 44 65 66 61 75 6c 74 20 54 61 62 5c 50 [0-6] 61 66 66 69 64 00 00 00 75 69 64}  //weight: 1, accuracy: Low
        $x_1_4 = "set_home_page_on_update" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule BrowserModifier_Win32_DefaultTab_207033_1
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/DefaultTab"
        threat_id = "207033"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "DefaultTab"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "npDefaultTabSearch.dll" ascii //weight: 1
        $x_1_2 = "ReleasenpDefaultTabSearch.pdb" ascii //weight: 1
        $x_1_3 = "DefaultTab\\uid" ascii //weight: 1
        $x_1_4 = "Global\\Default_Tab_Search_Results_ServiceReady" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

