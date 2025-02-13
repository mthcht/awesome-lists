rule PUA_Win32_OneSystemCare_225007_0
{
    meta:
        author = "defender2yara"
        detection_name = "PUA:Win32/OneSystemCare"
        threat_id = "225007"
        type = "PUA"
        platform = "Win32: Windows 32-bit platform"
        family = "OneSystemCare"
        severity = "7"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "IDB_POPUP_ICON_REGISTRY_CUSTOMIZE" wide //weight: 1
        $x_1_2 = "IDB_BTN_CLEAN_NOW1" wide //weight: 1
        $x_1_3 = "TXT_DIALOG_MAIN_2\">Performance</element>" ascii //weight: 1
        $x_1_4 = "\">Show me a full system report, " ascii //weight: 1
        $x_1_5 = "LBL_MESSY_MANY" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

