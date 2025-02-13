rule BrowserModifier_Win32_Istbar_F_7457_0
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Istbar.F"
        threat_id = "7457"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Istbar"
        severity = "40"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = "http://www.slotch.com/ist/softwares/v4.0/istdownload.exe" ascii //weight: 20
        $x_1_2 = {00 49 53 54 00}  //weight: 1, accuracy: High
        $x_1_3 = {61 69 64 3a [0-21] 20 2f 63 66 67 3a}  //weight: 1, accuracy: Low
        $x_1_4 = "546333sdfgsdfgfgdfsgsdfgsdfg6" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*))) or
            (all of ($x*))
        )
}

rule BrowserModifier_Win32_Istbar_F_7457_1
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Istbar.F"
        threat_id = "7457"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Istbar"
        severity = "40"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "/ist/scripts/ist" ascii //weight: 5
        $x_3_2 = "Software\\IST" ascii //weight: 3
        $x_5_3 = "/soft:istdownload" ascii //weight: 5
        $x_5_4 = "{771A1334-6B08-4a6b-AEDC-CF994B" ascii //weight: 5
        $x_5_5 = "ysb_cheat" ascii //weight: 5
        $x_3_6 = "slotch.com/" ascii //weight: 3
        $x_5_7 = "couldnotfind.com/search_page.html?" ascii //weight: 5
        $x_3_8 = "install.xxxtoolbar.com" ascii //weight: 3
        $x_3_9 = "ISTsvc" ascii //weight: 3
        $x_3_10 = "istsvc_installed=%" ascii //weight: 3
        $x_3_11 = "IST Service" ascii //weight: 3
        $x_2_12 = "popup_initial_delay" ascii //weight: 2
        $x_2_13 = "popup_interval" ascii //weight: 2
        $x_2_14 = "popup_day_count" ascii //weight: 2
        $x_2_15 = "type=istsvc&" ascii //weight: 2
        $x_2_16 = "&account_id=%" ascii //weight: 2
        $x_2_17 = "install_date=%s" ascii //weight: 2
        $x_3_18 = "Uninstall\\ISTsvc" ascii //weight: 3
        $x_8_19 = "Are you sure you want to remove IST" ascii //weight: 8
        $x_8_20 = "Some free software require IST" ascii //weight: 8
        $x_5_21 = "istsvc_del.bat" ascii //weight: 5
        $x_5_22 = "ISTsvcMUTEX" ascii //weight: 5
        $x_5_23 = "771A1334-6B08-4a6b-AEDC-CF994BA" ascii //weight: 5
        $x_5_24 = "istsvc:sf:redirector:" ascii //weight: 5
        $x_1_25 = "ist=%i" ascii //weight: 1
        $x_1_26 = "&istbar=%i" ascii //weight: 1
        $x_1_27 = "&istsvc=%i" ascii //weight: 1
        $x_1_28 = "&ncase=%i" ascii //weight: 1
        $x_1_29 = "&power=%i&cp=%i" ascii //weight: 1
        $x_1_30 = "&whenu=%i" ascii //weight: 1
        $x_1_31 = "&ign=%i&sf=%i" ascii //weight: 1
        $x_1_32 = "&ysb=%i&hli=%i" ascii //weight: 1
        $x_1_33 = "&euni=%i&glo=%i&web=%i" ascii //weight: 1
        $x_1_34 = "&tsa=%i" ascii //weight: 1
        $x_1_35 = "&sah=%i" ascii //weight: 1
        $x_1_36 = "&dh=%i&spo2=%i" ascii //weight: 1
        $x_1_37 = "&sacc=%i" ascii //weight: 1
        $x_1_38 = "&download_key=%s" ascii //weight: 1
        $x_1_39 = "&download_lock=%s" ascii //weight: 1
        $x_1_40 = "&cfg=%s&software_id=%s" ascii //weight: 1
        $x_1_41 = "#PURE_MAGIC" ascii //weight: 1
        $x_5_42 = "/soft:istsvc /version:%i" ascii //weight: 5
        $x_3_43 = "018B7EC3-EECA-11D3-8E71-0000E82C6C0D" ascii //weight: 3
        $x_3_44 = "EF86873F-04C2-4a95-A373-5703C08EFC7B" ascii //weight: 3
        $x_3_45 = "12398DD6-40AA-4c40-A4EC-A42CFC0DE797" ascii //weight: 3
        $x_2_46 = "c:\\vmcheck.dll" ascii //weight: 2
        $x_5_47 = "/istdownload_url_log.php" ascii //weight: 5
        $x_5_48 = "/ist_debug_new" ascii //weight: 5
        $n_10_49 = "AVREP.dll" ascii //weight: -10
        $n_10_50 = "PestPatrol" wide //weight: -10
        $n_300_51 = "Echo Bienvenue sur ToolbarShooter" ascii //weight: -300
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((2 of ($x_2_*) and 16 of ($x_1_*))) or
            ((3 of ($x_2_*) and 14 of ($x_1_*))) or
            ((4 of ($x_2_*) and 12 of ($x_1_*))) or
            ((5 of ($x_2_*) and 10 of ($x_1_*))) or
            ((6 of ($x_2_*) and 8 of ($x_1_*))) or
            ((7 of ($x_2_*) and 6 of ($x_1_*))) or
            ((1 of ($x_3_*) and 17 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 15 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*) and 13 of ($x_1_*))) or
            ((1 of ($x_3_*) and 3 of ($x_2_*) and 11 of ($x_1_*))) or
            ((1 of ($x_3_*) and 4 of ($x_2_*) and 9 of ($x_1_*))) or
            ((1 of ($x_3_*) and 5 of ($x_2_*) and 7 of ($x_1_*))) or
            ((1 of ($x_3_*) and 6 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_3_*) and 7 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_3_*) and 14 of ($x_1_*))) or
            ((2 of ($x_3_*) and 1 of ($x_2_*) and 12 of ($x_1_*))) or
            ((2 of ($x_3_*) and 2 of ($x_2_*) and 10 of ($x_1_*))) or
            ((2 of ($x_3_*) and 3 of ($x_2_*) and 8 of ($x_1_*))) or
            ((2 of ($x_3_*) and 4 of ($x_2_*) and 6 of ($x_1_*))) or
            ((2 of ($x_3_*) and 5 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_3_*) and 6 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_3_*) and 7 of ($x_2_*))) or
            ((3 of ($x_3_*) and 11 of ($x_1_*))) or
            ((3 of ($x_3_*) and 1 of ($x_2_*) and 9 of ($x_1_*))) or
            ((3 of ($x_3_*) and 2 of ($x_2_*) and 7 of ($x_1_*))) or
            ((3 of ($x_3_*) and 3 of ($x_2_*) and 5 of ($x_1_*))) or
            ((3 of ($x_3_*) and 4 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_3_*) and 5 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_3_*) and 6 of ($x_2_*))) or
            ((4 of ($x_3_*) and 8 of ($x_1_*))) or
            ((4 of ($x_3_*) and 1 of ($x_2_*) and 6 of ($x_1_*))) or
            ((4 of ($x_3_*) and 2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((4 of ($x_3_*) and 3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((4 of ($x_3_*) and 4 of ($x_2_*))) or
            ((5 of ($x_3_*) and 5 of ($x_1_*))) or
            ((5 of ($x_3_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((5 of ($x_3_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((5 of ($x_3_*) and 3 of ($x_2_*))) or
            ((6 of ($x_3_*) and 2 of ($x_1_*))) or
            ((6 of ($x_3_*) and 1 of ($x_2_*))) or
            ((7 of ($x_3_*))) or
            ((1 of ($x_5_*) and 15 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_2_*) and 13 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_2_*) and 11 of ($x_1_*))) or
            ((1 of ($x_5_*) and 3 of ($x_2_*) and 9 of ($x_1_*))) or
            ((1 of ($x_5_*) and 4 of ($x_2_*) and 7 of ($x_1_*))) or
            ((1 of ($x_5_*) and 5 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_5_*) and 6 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_5_*) and 7 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_3_*) and 12 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 10 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 8 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_3_*) and 3 of ($x_2_*) and 6 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_3_*) and 4 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_3_*) and 5 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_3_*) and 6 of ($x_2_*))) or
            ((1 of ($x_5_*) and 2 of ($x_3_*) and 9 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_3_*) and 1 of ($x_2_*) and 7 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_3_*) and 2 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_3_*) and 3 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_3_*) and 4 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_3_*) and 5 of ($x_2_*))) or
            ((1 of ($x_5_*) and 3 of ($x_3_*) and 6 of ($x_1_*))) or
            ((1 of ($x_5_*) and 3 of ($x_3_*) and 1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_5_*) and 3 of ($x_3_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_5_*) and 3 of ($x_3_*) and 3 of ($x_2_*))) or
            ((1 of ($x_5_*) and 4 of ($x_3_*) and 3 of ($x_1_*))) or
            ((1 of ($x_5_*) and 4 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_5_*) and 4 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_5_*) and 5 of ($x_3_*))) or
            ((2 of ($x_5_*) and 10 of ($x_1_*))) or
            ((2 of ($x_5_*) and 1 of ($x_2_*) and 8 of ($x_1_*))) or
            ((2 of ($x_5_*) and 2 of ($x_2_*) and 6 of ($x_1_*))) or
            ((2 of ($x_5_*) and 3 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_5_*) and 4 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_5_*) and 5 of ($x_2_*))) or
            ((2 of ($x_5_*) and 1 of ($x_3_*) and 7 of ($x_1_*))) or
            ((2 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((2 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_5_*) and 1 of ($x_3_*) and 3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_5_*) and 1 of ($x_3_*) and 4 of ($x_2_*))) or
            ((2 of ($x_5_*) and 2 of ($x_3_*) and 4 of ($x_1_*))) or
            ((2 of ($x_5_*) and 2 of ($x_3_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_5_*) and 2 of ($x_3_*) and 2 of ($x_2_*))) or
            ((2 of ($x_5_*) and 3 of ($x_3_*) and 1 of ($x_1_*))) or
            ((2 of ($x_5_*) and 3 of ($x_3_*) and 1 of ($x_2_*))) or
            ((2 of ($x_5_*) and 4 of ($x_3_*))) or
            ((3 of ($x_5_*) and 5 of ($x_1_*))) or
            ((3 of ($x_5_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_5_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_5_*) and 3 of ($x_2_*))) or
            ((3 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((3 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((3 of ($x_5_*) and 2 of ($x_3_*))) or
            ((4 of ($x_5_*))) or
            ((1 of ($x_8_*) and 12 of ($x_1_*))) or
            ((1 of ($x_8_*) and 1 of ($x_2_*) and 10 of ($x_1_*))) or
            ((1 of ($x_8_*) and 2 of ($x_2_*) and 8 of ($x_1_*))) or
            ((1 of ($x_8_*) and 3 of ($x_2_*) and 6 of ($x_1_*))) or
            ((1 of ($x_8_*) and 4 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_8_*) and 5 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_8_*) and 6 of ($x_2_*))) or
            ((1 of ($x_8_*) and 1 of ($x_3_*) and 9 of ($x_1_*))) or
            ((1 of ($x_8_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 7 of ($x_1_*))) or
            ((1 of ($x_8_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_8_*) and 1 of ($x_3_*) and 3 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_8_*) and 1 of ($x_3_*) and 4 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_8_*) and 1 of ($x_3_*) and 5 of ($x_2_*))) or
            ((1 of ($x_8_*) and 2 of ($x_3_*) and 6 of ($x_1_*))) or
            ((1 of ($x_8_*) and 2 of ($x_3_*) and 1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_8_*) and 2 of ($x_3_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_8_*) and 2 of ($x_3_*) and 3 of ($x_2_*))) or
            ((1 of ($x_8_*) and 3 of ($x_3_*) and 3 of ($x_1_*))) or
            ((1 of ($x_8_*) and 3 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_8_*) and 3 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_8_*) and 4 of ($x_3_*))) or
            ((1 of ($x_8_*) and 1 of ($x_5_*) and 7 of ($x_1_*))) or
            ((1 of ($x_8_*) and 1 of ($x_5_*) and 1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_8_*) and 1 of ($x_5_*) and 2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_8_*) and 1 of ($x_5_*) and 3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_8_*) and 1 of ($x_5_*) and 4 of ($x_2_*))) or
            ((1 of ($x_8_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 4 of ($x_1_*))) or
            ((1 of ($x_8_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_8_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_8_*) and 1 of ($x_5_*) and 2 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_8_*) and 1 of ($x_5_*) and 2 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_8_*) and 1 of ($x_5_*) and 3 of ($x_3_*))) or
            ((1 of ($x_8_*) and 2 of ($x_5_*) and 2 of ($x_1_*))) or
            ((1 of ($x_8_*) and 2 of ($x_5_*) and 1 of ($x_2_*))) or
            ((1 of ($x_8_*) and 2 of ($x_5_*) and 1 of ($x_3_*))) or
            ((1 of ($x_8_*) and 3 of ($x_5_*))) or
            ((2 of ($x_8_*) and 4 of ($x_1_*))) or
            ((2 of ($x_8_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_8_*) and 2 of ($x_2_*))) or
            ((2 of ($x_8_*) and 1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((2 of ($x_8_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((2 of ($x_8_*) and 2 of ($x_3_*))) or
            ((2 of ($x_8_*) and 1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule BrowserModifier_Win32_Istbar_D_14817_0
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Istbar.D"
        threat_id = "14817"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Istbar"
        severity = "25"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "band.dll" ascii //weight: 1
        $x_1_2 = "00021494-0000-0000-C000-000000000046" ascii //weight: 1
        $x_1_3 = "C7994E30-3427-475b-9E6A-854016870CD6" ascii //weight: 1
        $x_1_4 = "Software\\hycg\\hycg" ascii //weight: 1
        $x_1_5 = "hycg_Main" ascii //weight: 1
        $x_1_6 = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Discardable\\PostSetup\\Component Categories\\" ascii //weight: 1
        $x_1_7 = "GetWindowsDirectoryA" ascii //weight: 1
        $x_1_8 = "DllRegisterServer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule BrowserModifier_Win32_Istbar_D_14817_1
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Istbar.D"
        threat_id = "14817"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Istbar"
        severity = "25"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "{8CBA1B49-8144-4721-A7B1-64C578C9EED7}" ascii //weight: 1
        $x_1_2 = {53 69 64 65 46 69 6e 64 00}  //weight: 1, accuracy: High
        $x_1_3 = "shoppingautosearch" ascii //weight: 1
        $x_1_4 = "webautosearch" ascii //weight: 1
        $x_1_5 = {53 65 61 72 63 68 53 69 74 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule BrowserModifier_Win32_Istbar_D_14817_2
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Istbar.D"
        threat_id = "14817"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Istbar"
        severity = "25"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SOFTWARE\\Microsoft\\SideFind" ascii //weight: 1
        $x_1_2 = "Software\\Microsoft\\Internet Explorer\\Explorer Bars\\{8CBA1B49-8144-4721-A7B1-64C578C9EED7}" ascii //weight: 1
        $x_1_3 = "SearchSite" ascii //weight: 1
        $x_1_4 = "SOFTWARE\\SideFind\\History" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule BrowserModifier_Win32_Istbar_C_15569_0
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Istbar.C"
        threat_id = "15569"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Istbar"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "install.xxxtoolbar.com" ascii //weight: 2
        $x_2_2 = "www.ysbweb.com" ascii //weight: 2
        $x_2_3 = "www.slotch.com" ascii //weight: 2
        $x_2_4 = "cdn.climaxbucks.com" ascii //weight: 2
        $x_2_5 = "www.sp2admin.biz" ascii //weight: 2
        $x_2_6 = "ysb_m3" ascii //weight: 2
        $x_2_7 = "ysb_mp3" ascii //weight: 2
        $x_2_8 = "ysb_cheat" ascii //weight: 2
        $x_2_9 = "ysb_demo" ascii //weight: 2
        $x_2_10 = "%s?cfg=%s&account_id=%s" ascii //weight: 2
        $x_2_11 = "KWaeyg5Ko7aojc9" ascii //weight: 2
        $x_2_12 = "%s?aid=%i&cfg=%s&vkey=%s" ascii //weight: 2
        $x_2_13 = "/PC=CP.IST " ascii //weight: 2
        $x_1_14 = "/aid:" ascii //weight: 1
        $x_1_15 = "/cfg:" ascii //weight: 1
        $x_1_16 = "Software\\IST" ascii //weight: 1
        $x_1_17 = "istbar" ascii //weight: 1
        $x_1_18 = "BandRest" ascii //weight: 1
        $x_1_19 = "%s /sub:%s" ascii //weight: 1
        $x_1_20 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 6 of ($x_1_*))) or
            ((2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((4 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule BrowserModifier_Win32_Istbar_C_15569_1
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Istbar.C"
        threat_id = "15569"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Istbar"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "ISTactivex.DLL" ascii //weight: 10
        $x_3_2 = "download_lock" wide //weight: 3
        $x_3_3 = "download_key" wide //weight: 3
        $x_1_4 = "account_id" wide //weight: 1
        $x_2_5 = "CLDESC" wide //weight: 2
        $x_2_6 = "CLNAME" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_10_*) and 2 of ($x_3_*))) or
            (all of ($x*))
        )
}

