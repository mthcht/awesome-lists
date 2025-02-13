rule Trojan_MSIL_Genpacker_A_2147707708_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Genpacker.A"
        threat_id = "2147707708"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Genpacker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5f 07 25 17 58 0b 61 d2 0d 25 1e 63 07 25 17 58 0b 61 d2 13 04 26 11 04 09 13 04 0d 11 04 1e 62 09 60 d1 9d 17 58}  //weight: 1, accuracy: High
        $x_1_2 = "UsbDetector" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

