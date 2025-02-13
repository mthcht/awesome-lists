rule TrojanSpy_Win32_Yewlo_A_2147644297_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Yewlo.A"
        threat_id = "2147644297"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Yewlo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "To: arsenarsenddd@mail.ru" ascii //weight: 1
        $x_1_2 = "Black Engine 0x" ascii //weight: 1
        $x_1_3 = "[CURRENT WINDOW TEXT:%s]" ascii //weight: 1
        $x_1_4 = "/LIVE IN MY HEART MOTHER." ascii //weight: 1
        $x_1_5 = {43 00 3a 00 5c 00 54 00 45 00 4d 00 50 00 5c 00 73 00 76 00 63 00 68 00 6f 00 73 00 74 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

