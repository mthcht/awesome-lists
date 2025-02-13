rule Ransom_Win32_Korasom_A_2147722424_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Korasom.A"
        threat_id = "2147722424"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Korasom"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "YOU HAVE BEEN INFECTED WITH RANSOMWARE" ascii //weight: 1
        $x_1_2 = "Payment procedure" ascii //weight: 1
        $x_1_3 = "karo.ReadMe.html" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

