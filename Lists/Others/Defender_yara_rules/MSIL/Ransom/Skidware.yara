rule Ransom_MSIL_Skidware_PI_2147754960_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Skidware.PI!MTB"
        threat_id = "2147754960"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Skidware"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "If you click ok ur fudged." wide //weight: 1
        $x_1_2 = ".dodged" wide //weight: 1
        $x_1_3 = {5c 00 4d 00 49 00 43 00 52 00 4f 00 53 00 4f 00 46 00 54 00 2d 00 4c 00 4f 00 47 00 [0-4] 2e 00 74 00 78 00 74 00}  //weight: 1, accuracy: Low
        $x_1_4 = "Your PC has been locked" wide //weight: 1
        $x_1_5 = {59 00 6f 00 75 00 20 00 4d 00 55 00 53 00 54 00 20 00 70 00 61 00 79 00 20 00 [0-16] 20 00 42 00 49 00 54 00 43 00 4f 00 49 00 4e 00 20 00 61 00 74 00 20 00 74 00 68 00 65 00 20 00 66 00 6f 00 6c 00 6c 00 6f 00 77 00 69 00 6e 00 67 00 20 00 70 00 61 00 67 00 65 00 20 00 61 00 64 00 64 00 72 00 65 00 73 00 73 00 20 00 69 00 6e 00 20 00 6f 00 72 00 64 00 65 00 72 00 20 00 74 00 6f 00 20 00 67 00 65 00 74 00 20 00 79 00 6f 00 75 00 72 00 20 00 66 00 69 00 6c 00 65 00 73 00 20 00 62 00 61 00 63 00 6b 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

