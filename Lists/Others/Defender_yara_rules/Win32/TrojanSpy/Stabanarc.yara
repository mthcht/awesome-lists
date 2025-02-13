rule TrojanSpy_Win32_Stabanarc_A_2147627054_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Stabanarc.A"
        threat_id = "2147627054"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Stabanarc"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "del /Q /F /A=-L" ascii //weight: 1
        $x_1_2 = "American Express" ascii //weight: 1
        $x_1_3 = "Visa" ascii //weight: 1
        $x_1_4 = "MasterCard" ascii //weight: 1
        $x_1_5 = "DISCOVER" ascii //weight: 1
        $x_1_6 = "wupdmgr_update.exe" ascii //weight: 1
        $x_1_7 = "*clickbank*" ascii //weight: 1
        $x_1_8 = "*fastspring*" ascii //weight: 1
        $x_1_9 = "*esellerate*" ascii //weight: 1
        $x_1_10 = "confirm:card_" ascii //weight: 1
        $x_1_11 = "*pageconfirmation*" ascii //weight: 1
        $x_1_12 = "info.cc" ascii //weight: 1
        $x_1_13 = "*billing" ascii //weight: 1
        $x_1_14 = "*payment" ascii //weight: 1
        $x_1_15 = "*display*none*" ascii //weight: 1
        $x_1_16 = "*county*city*" ascii //weight: 1
        $x_1_17 = "*display*inline*color*red*" ascii //weight: 1
        $x_1_18 = "-infect=" ascii //weight: 1
        $x_1_19 = "-selfcure" ascii //weight: 1
        $x_1_20 = "%s\\trash%X" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (16 of ($x*))
}

