rule TrojanSpy_Win32_Eykspini_A_2147638157_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Eykspini.A"
        threat_id = "2147638157"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Eykspini"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "KeyBoardSpy.vbp" wide //weight: 1
        $x_1_2 = "Key_spy : " ascii //weight: 1
        $x_1_3 = "msdfmap.ini" wide //weight: 1
        $x_1_4 = {47 65 74 41 73 79 6e 63 4b 65 79 53 74 61 74 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

