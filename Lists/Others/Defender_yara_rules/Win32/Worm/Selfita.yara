rule Worm_Win32_Selfita_A_2147717191_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Selfita.A"
        threat_id = "2147717191"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Selfita"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\0vbcode\\gethtml\\Project1.vbp" wide //weight: 1
        $x_1_2 = "Converting exe to txt c:\\loadme.txt" wide //weight: 1
        $x_1_3 = "198.173.124.107/setup.html" ascii //weight: 1
        $x_1_4 = {49 6e 66 65 63 74 5f 44 72 69 76 65 73 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

