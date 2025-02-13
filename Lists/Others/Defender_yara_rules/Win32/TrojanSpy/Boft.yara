rule TrojanSpy_Win32_Boft_A_2147683185_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Boft.A"
        threat_id = "2147683185"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Boft"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "3BE3042CCD638DB858E711CB7C9F53" wide //weight: 5
        $x_2_2 = "828CBA79AD5D83A1BD0725C37DD16F9753FC69" wide //weight: 2
        $x_2_3 = "071335CE7EAC8D92478A97B675FA18C3B643E86FC7" wide //weight: 2
        $x_1_4 = "88B5519142E81915" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

