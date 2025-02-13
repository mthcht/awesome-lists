rule TrojanSpy_Win32_Warpp_A_2147691808_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Warpp.A"
        threat_id = "2147691808"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Warpp"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Logging of keystrokes is switched ON" wide //weight: 1
        $x_1_2 = {45 51 77 65 72 74 79 5f 64 72 69 76 65 72 53 74 61 74 75 73 43 6f 6d 6d 61 6e 64 20 74 6f 20 74 68 65 20 69 6d 70 6c 61 6e 74 2e 00}  //weight: 1, accuracy: High
        $x_1_3 = "implant failed to return a valid status" ascii //weight: 1
        $x_1_4 = "Qwerty FAILED to retrieve window list." wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

