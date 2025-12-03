rule TrojanSpy_Win32_Darkcloud_A_2147958716_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Darkcloud.A!AMTB"
        threat_id = "2147958716"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Darkcloud"
        severity = "Critical"
        info = "AMTB: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ScreenCapture" ascii //weight: 1
        $x_1_2 = "GetKeyboardData" ascii //weight: 1
        $x_1_3 = "card_number_encrypted" ascii //weight: 1
        $x_1_4 = "\\Screenshot_" ascii //weight: 1
        $x_1_5 = "Cookies" ascii //weight: 1
        $x_1_6 = "Contacts" ascii //weight: 1
        $x_1_7 = "\\KeyData_" ascii //weight: 1
        $x_1_8 = "\\LoginData" ascii //weight: 1
        $x_1_9 = "\\WebData" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (8 of ($x*))
}

