rule Ransom_Win32_Ophionlock_A_2147690652_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Ophionlock.A"
        threat_id = "2147690652"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Ophionlock"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {26 66 69 72 73 74 3d 31 00}  //weight: 1, accuracy: High
        $x_1_2 = {65 63 69 65 73 2e 70 75 62 6c 69 63 2e 6b 65 79 00}  //weight: 1, accuracy: High
        $x_1_3 = "won't EVER get your files back." ascii //weight: 1
        $x_1_4 = "your hwid is :" ascii //weight: 1
        $x_1_5 = {2e 70 68 70 3f 68 77 69 64 3d 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

