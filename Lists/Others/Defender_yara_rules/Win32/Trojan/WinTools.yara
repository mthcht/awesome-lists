rule Trojan_Win32_WinTools_14772_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/WinTools"
        threat_id = "14772"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "WinTools"
        severity = "32"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ASK_ENABLE_HOMEPAGE" ascii //weight: 1
        $x_1_2 = "AdSWndProc" ascii //weight: 1
        $x_1_3 = "Software\\WinTools" ascii //weight: 1
        $x_1_4 = "WToolsB.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_WinTools_14772_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/WinTools"
        threat_id = "14772"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "WinTools"
        severity = "32"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 1
        $x_1_2 = "WebSearch Toolbar\\" ascii //weight: 1
        $x_1_3 = {43 4c 53 49 44 5c 7b 00 ff ff ff ff 01 00 00 00 2d 00 00 00 ff ff ff ff 06 00 00 00 2d 42 32 33 44 2d 00 00 ff ff ff ff 01 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_WinTools_14772_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/WinTools"
        threat_id = "14772"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "WinTools"
        severity = "32"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 1
        $x_1_2 = "WebSearch Easy Installer" ascii //weight: 1
        $x_1_3 = "WinTools\\" ascii //weight: 1
        $x_1_4 = "wtoolsa.exe" ascii //weight: 1
        $x_1_5 = "CLSID\\{87067F04-DE4C-4688-BC3C-4FCF39D609E7}" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_WinTools_14772_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/WinTools"
        threat_id = "14772"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "WinTools"
        severity = "32"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Did you know all the advantages of the WebSearch Toolbar?" ascii //weight: 1
        $x_1_2 = "WARNING! You may have Spyware on your PC without your knowledge!" ascii //weight: 1
        $x_1_3 = "TBPS.exe /installskin" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_WinTools_14772_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/WinTools"
        threat_id = "14772"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "WinTools"
        severity = "32"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 5
        $x_5_2 = "xr2ywrx7" ascii //weight: 5
        $x_5_3 = "Software\\WinTools\\kydmzylki" ascii //weight: 5
        $x_1_4 = "WToolsA.exe" ascii //weight: 1
        $x_1_5 = "WToolsB.dll" ascii //weight: 1
        $x_1_6 = "WToolsC.cfg" ascii //weight: 1
        $x_1_7 = "WToolsP.cfg" ascii //weight: 1
        $x_1_8 = "WToolsD.cfg" ascii //weight: 1
        $x_1_9 = {41 5f 53 5f 56 5f 32 ?? 43 6c 6f 73 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 6 of ($x_1_*))) or
            ((3 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_WinTools_14772_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/WinTools"
        threat_id = "14772"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "WinTools"
        severity = "32"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "32"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 10
        $x_10_2 = "Win-Tools Easy Installer Uninstallation Progress" ascii //weight: 10
        $x_10_3 = "Did you know all the advantages the WinTools?" ascii //weight: 10
        $x_2_4 = "WToolsB.dll" ascii //weight: 2
        $x_2_5 = "WToolsA.exe" ascii //weight: 2
        $x_1_6 = "%c_hist%" ascii //weight: 1
        $x_1_7 = "</show_ad>" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 2 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_WinTools_14772_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/WinTools"
        threat_id = "14772"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "WinTools"
        severity = "32"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "41"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 10
        $x_10_2 = "WToolsA.exe" ascii //weight: 10
        $x_10_3 = "WToolsB.dll" ascii //weight: 10
        $x_2_4 = "WToolsC.cfg" ascii //weight: 2
        $x_2_5 = "WToolsP.cfg" ascii //weight: 2
        $x_2_6 = "WToolsD.cfg" ascii //weight: 2
        $x_2_7 = "WToolsS.exe" ascii //weight: 2
        $x_2_8 = "Common files\\WinTools" ascii //weight: 2
        $x_1_9 = "AdSupportUnbreak" ascii //weight: 1
        $x_1_10 = "</show_ad>" ascii //weight: 1
        $x_1_11 = "%c_hist%" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 4 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_10_*) and 5 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_WinTools_14772_7
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/WinTools"
        threat_id = "14772"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "WinTools"
        severity = "32"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 1
        $x_1_2 = "WebSearch Downloader" ascii //weight: 1
        $x_1_3 = "WebSearch Toolbar Update" ascii //weight: 1
        $x_1_4 = "The toolbar has been successfully updated!" ascii //weight: 1
        $x_1_5 = "Would you like restart your computer to make the change take effect?" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_WinTools_14772_8
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/WinTools"
        threat_id = "14772"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "WinTools"
        severity = "32"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_15_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 15
        $x_5_2 = "AS_V_2_Hook_Map" ascii //weight: 5
        $x_5_3 = "ASV2_HookMtx" ascii //weight: 5
        $x_5_4 = "A_S_V_2_Mtx" ascii //weight: 5
        $x_3_5 = "A_S_V_2_Close" ascii //weight: 3
        $x_3_6 = "ST_V_3_Hook_Map" ascii //weight: 3
        $x_3_7 = "websearch.com" ascii //weight: 3
        $x_3_8 = "adwave.com" ascii //weight: 3
        $x_2_9 = "WToolsA.exe" ascii //weight: 2
        $x_2_10 = "WToolsB.dll" ascii //weight: 2
        $x_2_11 = "WSup.exe" ascii //weight: 2
        $x_1_12 = "AdSWndProc" ascii //weight: 1
        $x_1_13 = "AdSupportUnbreak" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 4 of ($x_3_*) and 3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_5_*) and 3 of ($x_3_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_5_*) and 3 of ($x_3_*) and 3 of ($x_2_*))) or
            ((2 of ($x_5_*) and 4 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_5_*) and 4 of ($x_3_*) and 2 of ($x_2_*))) or
            ((3 of ($x_5_*) and 1 of ($x_3_*) and 3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_5_*) and 2 of ($x_3_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_5_*) and 2 of ($x_3_*) and 2 of ($x_2_*))) or
            ((3 of ($x_5_*) and 3 of ($x_3_*) and 1 of ($x_1_*))) or
            ((3 of ($x_5_*) and 3 of ($x_3_*) and 1 of ($x_2_*))) or
            ((3 of ($x_5_*) and 4 of ($x_3_*))) or
            ((1 of ($x_15_*) and 1 of ($x_3_*) and 3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_15_*) and 2 of ($x_3_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_15_*) and 2 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_15_*) and 3 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_15_*) and 3 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_15_*) and 4 of ($x_3_*))) or
            ((1 of ($x_15_*) and 1 of ($x_5_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_15_*) and 1 of ($x_5_*) and 3 of ($x_2_*))) or
            ((1 of ($x_15_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_15_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_15_*) and 1 of ($x_5_*) and 2 of ($x_3_*))) or
            ((1 of ($x_15_*) and 2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_WinTools_14772_9
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/WinTools"
        threat_id = "14772"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "WinTools"
        severity = "32"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Portions Copyright (c) 1983,99 Borland" ascii //weight: 1
        $x_1_2 = "WinTools\\wtoolsa.exe" ascii //weight: 1
        $x_1_3 = "CLSID\\{87067F04-DE4C-4688-BC3C-4FCF39D609E7}" ascii //weight: 1
        $x_1_4 = {68 74 74 70 3a 2f 2f 64 6f 77 6e 6c 6f 61 64 2e 77 65 62 73 65 61 72 63 68 2e 63 6f 6d 2f 44 6e 6c 2f 54 5f ?? ?? ?? ?? ?? 2f 57 69 6e 54 6f 6f 6c 73 2e 63 61 62}  //weight: 1, accuracy: Low
        $x_1_5 = {68 74 74 70 3a 2f 2f 64 6f 77 6e 6c 6f 61 64 2e 77 65 62 73 65 61 72 63 68 2e 63 6f 6d 2f 54 62 [0-4] 49 6e 73 74 4c 6f 67 2e 61 73 6d 78 2f 47 65 74 58 4d 4c 3f 54 62 49 64 3d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_WinTools_14772_10
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/WinTools"
        threat_id = "14772"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "WinTools"
        severity = "32"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "29"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 20
        $x_4_2 = "DOWNLOAD=http://download.websearch.com/dnl/T" ascii //weight: 4
        $x_4_3 = "CLSID\\{339BB23F-A864-48C0-A59F-29EA915965EC}\\InProcServer32" ascii //weight: 4
        $x_3_4 = "Search Toolbar 2.0 from Web Search" ascii //weight: 3
        $x_1_5 = "win-tools.com/faq_st.aspx" ascii //weight: 1
        $x_1_6 = "websearch.com/legal" ascii //weight: 1
        $x_1_7 = "WINTOOLS END-USER LICENSE" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_20_*) and 2 of ($x_4_*) and 1 of ($x_1_*))) or
            ((1 of ($x_20_*) and 2 of ($x_4_*) and 1 of ($x_3_*))) or
            (all of ($x*))
        )
}

