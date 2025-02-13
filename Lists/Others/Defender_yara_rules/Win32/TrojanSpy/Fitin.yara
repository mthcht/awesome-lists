rule TrojanSpy_Win32_Fitin_A_2147658302_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Fitin.A"
        threat_id = "2147658302"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Fitin"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4e 00 65 00 77 00 20 00 49 00 6e 00 66 00 65 00 63 00 74 00 69 00 6f 00 6e 00 00 21 4e 00 65 00 77 00 20 00 49 00 6e 00 66 00 65 00 63 00 74 00 69 00 6f 00 6e 00 21 00 21 00 21}  //weight: 1, accuracy: High
        $x_1_2 = {2b 5d 00 3a 00 20 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 20 00 49 00 73 00 20 00 4f 00 66 00 66 00 20 00 4e 00 6f 00 77}  //weight: 1, accuracy: High
        $x_1_3 = "[Backspace]" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

