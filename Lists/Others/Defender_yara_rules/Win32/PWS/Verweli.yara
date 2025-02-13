rule PWS_Win32_Verweli_A_2147631363_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Verweli.A"
        threat_id = "2147631363"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Verweli"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "bBOMSU8t4Tq+/BmUaj9Glw==" ascii //weight: 1
        $x_1_2 = "6Uf/RegFpH7zGDzxH3tT6A==" ascii //weight: 1
        $x_1_3 = "VANe+lpxysacat3NGC/sjg==" ascii //weight: 1
        $x_1_4 = "Wj3eYCtWeEt8jqHUhCm0Vg==" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

