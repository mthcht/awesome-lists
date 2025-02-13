rule TrojanSpy_MSIL_Yakbeex_A_2147705993_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Yakbeex.A"
        threat_id = "2147705993"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Yakbeex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "=keystrokes&machinename=" wide //weight: 1
        $x_1_2 = "=passwords&machinename=" wide //weight: 1
        $x_1_3 = "=clipboard&machinename=" wide //weight: 1
        $x_1_4 = "=notification&machinename=" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanSpy_MSIL_Yakbeex_A_2147705993_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Yakbeex.A"
        threat_id = "2147705993"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Yakbeex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {62 61 72 6b 6c 6f 77 2e 65 78 65 00}  //weight: 2, accuracy: High
        $x_1_2 = {47 61 6d 69 6e 67 20 4d 6f 75 73 65 20 44 72 69 76 65 72 00}  //weight: 1, accuracy: High
        $x_1_3 = {61 00 31 00 66 00 34 00 36 00 66 00 31 00 30 00 2d 00 34 00 63 00 37 00 33 00 2d 00 34 00 61 00 39 00 34 00 2d 00 38 00 32 00 62 00 37 00 2d 00 34 00 66 00 32 00 64 00 30 00 61 00 35 00 33 00 37 00 30 00 65 00 61 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {5c 4f 62 66 75 73 63 61 74 65 64 5c 62 61 72 6b 6c 6f 77 2e 70 64 62 00}  //weight: 1, accuracy: High
        $x_1_5 = {44 6f 6d 61 69 6e 55 70 44 6f 77 6e 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_MSIL_Yakbeex_2147706448_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Yakbeex"
        threat_id = "2147706448"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Yakbeex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "17"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Facebook" ascii //weight: 1
        $x_1_2 = "Skype" ascii //weight: 1
        $x_1_3 = "vbox.exe" ascii //weight: 1
        $x_1_4 = "VboxService.exe" ascii //weight: 1
        $x_1_5 = "#NoTrayIcon" ascii //weight: 1
        $x_1_6 = "SEtFWV9DVVJSRU5UX1VTRVJcU29mdHdhcmVcTWljcm9zb2Z0XFdpbmRvd3NcQ3VycmVudFZlcnNpb25cUnVuT25jZVw=" ascii //weight: 1
        $x_1_7 = "vmware-tray.exe" ascii //weight: 1
        $x_1_8 = "Mr8ndv.exe" ascii //weight: 1
        $x_1_9 = "shark.exe" ascii //weight: 1
        $x_1_10 = "Dropbox\\host.db" ascii //weight: 1
        $x_1_11 = "\\shell\\open\\command" ascii //weight: 1
        $x_1_12 = "vmware-authd.exe" ascii //weight: 1
        $x_1_13 = "SbieCtrl" ascii //weight: 1
        $x_1_14 = "Sandboxie" ascii //weight: 1
        $x_1_15 = "\\SECRET.exe" ascii //weight: 1
        $x_1_16 = "^v{ENTER}" ascii //weight: 1
        $x_1_17 = "C:\\ProgramData\\cleanup.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_Yakbeex_B_2147706521_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Yakbeex.B"
        threat_id = "2147706521"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Yakbeex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {66 75 76 69 6f 6e 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_2 = {47 61 6d 69 6e 67 20 4d 6f 75 73 65 20 44 72 69 76 65 72 00}  //weight: 1, accuracy: High
        $x_1_3 = {4d 69 6f 43 61 72 64 00}  //weight: 1, accuracy: High
        $x_1_4 = {44 6f 6d 61 69 6e 55 70 44 6f 77 6e 00}  //weight: 1, accuracy: High
        $x_1_5 = {37 00 65 00 38 00 61 00 35 00 30 00 34 00 38 00 2d 00 63 00 64 00 39 00 30 00 2d 00 34 00 62 00 62 00 64 00 2d 00 62 00 30 00 63 00 38 00 2d 00 35 00 37 00 63 00 39 00 62 00 30 00 65 00 32 00 64 00 61 00 37 00 30 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanSpy_MSIL_Yakbeex_B_2147706521_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Yakbeex.B"
        threat_id = "2147706521"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Yakbeex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Keystrokes typed:" wide //weight: 1
        $x_1_2 = "KeyloggerProcess" ascii //weight: 1
        $x_1_3 = "PasswordRecovery" ascii //weight: 1
        $x_1_4 = "RecoverBrowsers" ascii //weight: 1
        $x_1_5 = "ScreenshotHotList" ascii //weight: 1
        $x_1_6 = "&keystrokestyped=" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

