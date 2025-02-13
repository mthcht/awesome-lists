rule Trojan_MSIL_Ficongur_A_2147717210_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Ficongur.A"
        threat_id = "2147717210"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Ficongur"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_8_1 = "_WORK\\encrypter" ascii //weight: 8
        $x_4_2 = "HiddenTear\\" ascii //weight: 4
        $x_4_3 = "hidden-tear-master" ascii //weight: 4
        $x_2_4 = "Myexperements" ascii //weight: 2
        $x_2_5 = "\\winupdate\\w" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_8_*) and 1 of ($x_4_*) and 1 of ($x_2_*))) or
            ((1 of ($x_8_*) and 2 of ($x_4_*))) or
            (all of ($x*))
        )
}

