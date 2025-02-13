rule Trojan_Win32_Bewter_A_2147706037_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bewter.A"
        threat_id = "2147706037"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bewter"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5c 00 52 00 75 00 6e 00 5c 00 57 00 65 00 62 00 43 00 6f 00 75 00 6e 00 74 00 65 00 72 00 00 00 34 00 00 00 5c 00 57 00 65 00 62 00 43 00 6f 00 75 00 6e 00 74 00 65 00 72 00 5c 00 57 00 65 00 62 00 43 00 6f 00 75 00 6e 00 74 00 65 00 72 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: High
        $x_1_2 = "theme.ir/seo/addres.html" wide //weight: 1
        $x_1_3 = {77 00 73 00 63 00 72 00 69 00 70 00 74 00 2e 00 73 00 68 00 65 00 6c 00 6c 00 00 00 82 00 00 00 48 00 4b 00 43 00 55 00 5c 00 53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00}  //weight: 1, accuracy: High
        $x_1_4 = "\\WebCounter\\Source\\WebCounter.vbp" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

