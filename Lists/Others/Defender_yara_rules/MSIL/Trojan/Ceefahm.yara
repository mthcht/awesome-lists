rule Trojan_MSIL_Ceefahm_A_2147663112_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Ceefahm.A"
        threat_id = "2147663112"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Ceefahm"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "aHR0cDovL2xvY2FsaG9zdC9yZWN2LnBocD9nZGF0YT0=" ascii //weight: 1
        $x_1_2 = "VXBsb2FkUmVwb3J0TG9naW4uYXNteA==" ascii //weight: 1
        $x_1_3 = "QXV0b1N0YXJ0VXAgTW9kdWxlIGhhcyBmYWlsZWQu" ascii //weight: 1
        $x_1_4 = "bGl0aWVzLmNvbS8=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

