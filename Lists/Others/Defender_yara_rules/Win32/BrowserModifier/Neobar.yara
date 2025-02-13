rule BrowserModifier_Win32_Neobar_225451_0
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Neobar"
        threat_id = "225451"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Neobar"
        severity = "24"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5c 00 54 00 6f 00 72 00 72 00 65 00 6e 00 74 00 20 00 53 00 65 00 61 00 72 00 63 00 68 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {2f 00 6e 00 72 00 70 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {2f 00 65 00 78 00 62 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = "Chromium.dll" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule BrowserModifier_Win32_Neobar_225451_1
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Neobar"
        threat_id = "225451"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Neobar"
        severity = "24"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Torrent Search Setup" wide //weight: 1
        $x_1_2 = "/not_install_toolbar" wide //weight: 1
        $x_1_3 = "\\uninstall.exe\" /exb \"" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule BrowserModifier_Win32_Neobar_225451_2
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Neobar"
        threat_id = "225451"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Neobar"
        severity = "24"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "61"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "BrowsersFix.js" wide //weight: 20
        $x_20_2 = "/not_install_toolbar" wide //weight: 20
        $x_20_3 = "api.appsapi.info/api" wide //weight: 20
        $x_1_4 = "\\Torrent Search" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule BrowserModifier_Win32_Neobar_225451_3
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Neobar"
        threat_id = "225451"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Neobar"
        severity = "24"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "41"
        strings_accuracy = "High"
    strings:
        $x_20_1 = {49 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 65 00 72 00 48 00 65 00 6c 00 70 00 65 00 72 00 50 00 61 00 63 00 6b 00 65 00 72 00 00 00}  //weight: 20, accuracy: High
        $x_20_2 = {41 00 56 00 45 00 78 00 63 00 6c 00 50 00 61 00 63 00 6b 00 65 00 72 00 00 00}  //weight: 20, accuracy: High
        $x_1_3 = {56 00 4b 00 20 00 4f 00 4b 00 20 00 41 00 64 00 42 00 6c 00 6f 00 63 00 6b 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {59 00 6f 00 75 00 74 00 75 00 62 00 65 00 20 00 41 00 64 00 42 00 6c 00 6f 00 63 00 6b 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {54 00 6f 00 72 00 72 00 65 00 6e 00 74 00 20 00 53 00 65 00 61 00 72 00 63 00 68 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_20_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule BrowserModifier_Win32_Neobar_225451_4
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Neobar"
        threat_id = "225451"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Neobar"
        severity = "24"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "/ts_big.exe" wide //weight: 1
        $x_1_2 = {72 00 61 00 70 00 69 00 64 00 66 00 69 00 6c 00 65 00 73 00 74 00 6f 00 72 00 61 00 67 00 65 00 2e 00 63 00 6f 00 6d 00 2f 00 75 00 70 00 64 00 61 00 74 00 65 00 73 00 2f 00 2b 03 03 00 2f 00 [0-32] 2f 00 75 00 70 00 64 00 61 00 74 00 65 00 [0-4] 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_3 = {66 00 69 00 6c 00 65 00 73 00 2e 00 61 00 70 00 70 00 73 00 61 00 70 00 69 00 2e 00 69 00 6e 00 66 00 6f 00 2f 00 75 00 70 00 64 00 61 00 74 00 65 00 73 00 2f 00 2b 03 03 00 2f 00 [0-32] 2f 00 75 00 70 00 64 00 61 00 74 00 65 00 [0-4] 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule BrowserModifier_Win32_Neobar_225451_5
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Neobar"
        threat_id = "225451"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Neobar"
        severity = "24"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "/extract_binaries" wide //weight: 20
        $x_1_2 = "Torrent Search" wide //weight: 1
        $x_1_3 = "VK OK AdBlock" wide //weight: 1
        $x_1_4 = "{6E727987-C8EA-44DA-8749-310C0FBE3C3E}" wide //weight: 1
        $x_1_5 = "{FF20459C-DA6E-41A7-80BC-8F4FEFD9C575}" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule BrowserModifier_Win32_Neobar_225451_6
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Neobar"
        threat_id = "225451"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Neobar"
        severity = "24"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "UpdateLatestVersionURL" wide //weight: 1
        $x_1_2 = "lastUpdateCheckTime" wide //weight: 1
        $x_1_3 = "/Configuration/Settings/UpdateErrorDelay" wide //weight: 1
        $x_1_4 = "/SUPPRESSMSGBOXES /NORESTART /S /UPDATE /VERYSILENT" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule BrowserModifier_Win32_Neobar_225451_7
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Neobar"
        threat_id = "225451"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Neobar"
        severity = "24"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "42"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "/not_install_toolbar" wide //weight: 20
        $x_20_2 = "\\uninstall.exe\" /extract_binaries \"" wide //weight: 20
        $x_1_3 = "SOFTWARE\\Torrent Search" wide //weight: 1
        $x_1_4 = "SOFTWARE\\VK OK AdBlock" wide //weight: 1
        $x_1_5 = "Torrent Search Setup" wide //weight: 1
        $x_1_6 = "VK OK AdBlock Setup" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_20_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule BrowserModifier_Win32_Neobar_225451_8
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Neobar"
        threat_id = "225451"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Neobar"
        severity = "24"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "ping.exe\" \"rapidfilestorage.com\" -n 1" wide //weight: 1
        $x_1_2 = "/SUPPRESSMSGBOXES /NORESTART /S /UPDATE /VERYSILENT" wide //weight: 1
        $x_1_3 = {72 00 61 00 70 00 69 00 64 00 66 00 69 00 6c 00 65 00 73 00 74 00 6f 00 72 00 61 00 67 00 65 00 2e 00 63 00 6f 00 6d 00 2f 00 75 00 70 00 64 00 61 00 74 00 65 00 73 00 2f 00 2b 03 03 00 2f 00 [0-32] 2f 00 75 00 70 00 64 00 61 00 74 00 65 00 [0-4] 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_4 = {66 00 69 00 6c 00 65 00 73 00 2e 00 61 00 70 00 70 00 73 00 61 00 70 00 69 00 2e 00 69 00 6e 00 66 00 6f 00 2f 00 75 00 70 00 64 00 61 00 74 00 65 00 73 00 2f 00 2b 03 03 00 2f 00 [0-32] 2f 00 2b 08 08 00 2e 00 74 00 78 00 74 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule BrowserModifier_Win32_Neobar_225451_9
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Neobar"
        threat_id = "225451"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Neobar"
        severity = "24"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Toolbar.ExtensionHelperObject" wide //weight: 1
        $x_1_2 = "addBrowsersFix" wide //weight: 1
        $x_1_3 = "UpdateService in OnStop" wide //weight: 1
        $x_1_4 = "updateJsonUrl" wide //weight: 1
        $x_1_5 = "--installrContainer" wide //weight: 1
        $x_1_6 = "_BackgroundBrowserContainer" wide //weight: 1
        $x_1_7 = "expand.exe \"%s\" -F:*.* \"%s\"" wide //weight: 1
        $x_1_8 = "InstallerCab.exe\" \"%s\\install.bat\"" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule BrowserModifier_Win32_Neobar_225451_10
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Neobar"
        threat_id = "225451"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Neobar"
        severity = "24"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_20_1 = {63 00 68 00 72 00 6f 00 6d 00 65 00 5c 00 4b 00 65 00 72 00 6e 00 65 00 6c 00 2e 00 6a 00 73 00 00 00}  //weight: 20, accuracy: High
        $x_1_2 = {59 00 6f 00 75 00 74 00 75 00 62 00 65 00 20 00 41 00 64 00 42 00 6c 00 6f 00 63 00 6b 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "95E84BD3-3604-4AAC-B2CA-D9AC3E55B64B" wide //weight: 1
        $x_1_4 = {59 00 6f 00 75 00 54 00 75 00 62 00 65 00 20 00 44 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 65 00 72 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = "96CEA7AF-360C-4F5E-94E6-5F54840340F2" wide //weight: 1
        $x_1_6 = {4d 00 65 00 64 00 69 00 61 00 20 00 53 00 61 00 76 00 65 00 72 00 00 00}  //weight: 1, accuracy: High
        $x_1_7 = "12E8A6C2-B125-479F-AB3C-13B8757C7F04" wide //weight: 1
        $x_1_8 = {54 00 6f 00 72 00 72 00 65 00 6e 00 74 00 20 00 53 00 65 00 61 00 72 00 63 00 68 00 00 00}  //weight: 1, accuracy: High
        $x_1_9 = "6E727987-C8EA-44DA-8749-310C0FBE3C3E" wide //weight: 1
        $x_1_10 = {56 00 4b 00 20 00 4f 00 4b 00 20 00 41 00 64 00 42 00 6c 00 6f 00 63 00 6b 00 00 00}  //weight: 1, accuracy: High
        $x_1_11 = "FF20459C-DA6E-41A7-80BC-8F4FEFD9C575" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule BrowserModifier_Win32_Neobar_225451_11
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Neobar"
        threat_id = "225451"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Neobar"
        severity = "24"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "32"
        strings_accuracy = "High"
    strings:
        $x_16_1 = {59 00 6f 00 75 00 74 00 75 00 62 00 65 00 20 00 41 00 64 00 42 00 6c 00 6f 00 63 00 6b 00 00 00}  //weight: 16, accuracy: High
        $x_16_2 = "{95E84BD3-3604-4AAC-B2CA-D9AC3E55B64B}" wide //weight: 16
        $x_16_3 = {59 00 6f 00 75 00 54 00 75 00 62 00 65 00 20 00 44 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 65 00 72 00 00 00}  //weight: 16, accuracy: High
        $x_16_4 = "{96CEA7AF-360C-4F5E-94E6-5F54840340F2}" wide //weight: 16
        $x_16_5 = "Media Saver" wide //weight: 16
        $x_16_6 = "{12E8A6C2-B125-479F-AB3C-13B8757C7F04}" wide //weight: 16
        $x_16_7 = {54 00 6f 00 72 00 72 00 65 00 6e 00 74 00 20 00 53 00 65 00 61 00 72 00 63 00 68 00 00 00}  //weight: 16, accuracy: High
        $x_16_8 = "{6E727987-C8EA-44DA-8749-310C0FBE3C3E}" wide //weight: 16
        $x_16_9 = {56 00 4b 00 20 00 4f 00 4b 00 20 00 41 00 64 00 42 00 6c 00 6f 00 63 00 6b 00 00 00}  //weight: 16, accuracy: High
        $x_16_10 = "{FF20459C-DA6E-41A7-80BC-8F4FEFD9C575}" wide //weight: 16
        $x_1_11 = "ABHTML_EXTENSION_AMIGO_FAKE_ID" wide //weight: 1
        $x_1_12 = "ABHTML_EXTENSION_AMIGO_FAKE_KEY" wide //weight: 1
        $x_1_13 = "/not_install_toolbar" wide //weight: 1
        $x_1_14 = "/set_homepage" wide //weight: 1
        $x_1_15 = "/fsuhsh" wide //weight: 1
        $x_1_16 = "/jfuklh" wide //weight: 1
        $x_1_17 = "/giudrsghdrsigh" wide //weight: 1
        $x_1_18 = "/gkg93jgh37fjgu" wide //weight: 1
        $x_1_19 = "/fR2jaW_" wide //weight: 1
        $x_1_20 = "/lr6qQ4W" wide //weight: 1
        $x_1_21 = "/UmgcTC9" wide //weight: 1
        $x_1_22 = "/WbEogRV" wide //weight: 1
        $x_1_23 = "/7EB4kNk" wide //weight: 1
        $x_1_24 = "::#51(*i r0r1)" wide //weight: 1
        $x_1_25 = "::#45(t .r7, i 0, i" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_16_*))) or
            (all of ($x*))
        )
}

