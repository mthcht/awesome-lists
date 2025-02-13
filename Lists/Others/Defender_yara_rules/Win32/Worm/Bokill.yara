rule Worm_Win32_Bokill_C_2147693168_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Bokill.C"
        threat_id = "2147693168"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Bokill"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FacebookSpread" ascii //weight: 1
        $x_1_2 = "TwitterSpreader" ascii //weight: 1
        $x_1_3 = "BotkillerDelayrestart" ascii //weight: 1
        $x_1_4 = "ContadorUAC" ascii //weight: 1
        $x_1_5 = "SendmessageSpreadFacebook" ascii //weight: 1
        $x_1_6 = "UnitKeylogger" wide //weight: 1
        $x_1_7 = "KillServiceav" ascii //weight: 1
        $x_1_8 = "usbspread" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule Worm_Win32_Bokill_D_2147697808_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Bokill.D"
        threat_id = "2147697808"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Bokill"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {50 72 6f 61 63 74 69 76 65 42 6f 74 6b 69 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_2 = {6d 6f 64 75 73 62 73 70 72 65 61 64 00}  //weight: 1, accuracy: High
        $x_1_3 = {6d 6f 64 42 6f 74 6b 69 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_4 = {6d 6f 64 61 76 6b 69 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_5 = {54 77 69 74 74 65 72 53 70 72 65 61 64 65 72 00}  //weight: 1, accuracy: High
        $x_1_6 = {53 65 6e 64 6d 65 73 73 61 67 65 53 70 72 65 61 64 46 61 63 65 62 6f 6f 6b 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

