rule Trojan_MSIL_Kosmoceratops_A_2147967305_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Kosmoceratops.A!dha"
        threat_id = "2147967305"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Kosmoceratops"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "HasInternetConnection" ascii //weight: 1
        $x_1_2 = "Window_Loaded" ascii //weight: 1
        $x_1_3 = {55 73 65 72 6e 61 6d 65 42 6f 78 5f 54 65 78 74 43 68 ?? 6e 67 65 64}  //weight: 1, accuracy: Low
        $x_1_4 = "Image files (*.jpg;*.jpeg;*.png;*.bmp;*.gif)|*.jpg;*.jpeg;*.png;*.bmp;*.gif" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

