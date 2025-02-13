rule TrojanClicker_Win32_Lnkwinkap_A_2147638679_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:Win32/Lnkwinkap.A"
        threat_id = "2147638679"
        type = "TrojanClicker"
        platform = "Win32: Windows 32-bit platform"
        family = "Lnkwinkap"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Windows Messenger.lnk" wide //weight: 1
        $x_1_2 = "Internet Explorer.lnk" wide //weight: 1
        $x_1_3 = "Notepad.lnk" wide //weight: 1
        $x_2_4 = {7e 19 66 83 7c 5e fe 2e 75 11 57}  //weight: 2, accuracy: High
        $x_2_5 = ":8080/sogouconfig/" ascii //weight: 2
        $x_2_6 = {69 23 63 25 6b 00}  //weight: 2, accuracy: High
        $x_2_7 = {43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 57 69 6e 50 63 61 70 [0-16] 2e 65 78 65 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

