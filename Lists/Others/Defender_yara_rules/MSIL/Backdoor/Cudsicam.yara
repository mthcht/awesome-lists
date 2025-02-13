rule Backdoor_MSIL_Cudsicam_A_2147658714_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Cudsicam.A"
        threat_id = "2147658714"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cudsicam"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {43 6d 64 53 75 69 63 69 64 00 53 75 69 63 69 64}  //weight: 1, accuracy: High
        $x_1_2 = {50 61 72 73 65 43 6f 6d 6d 61 6e 64 00 63 6f 6d 6d 61 6e 64 00 63 6f 6d 6d 61 6e 64 4e 61 6d 65}  //weight: 1, accuracy: High
        $x_1_3 = {43 6d 64 49 6e 73 74 61 6c 6c 00 57 65 62 43 6c 69 65 6e 74 00 53 79 73 74 65 6d 2e 4e 65 74}  //weight: 1, accuracy: High
        $x_1_4 = {46 6c 61 67 45 78 73 69 73 74 73 00 70 72 6d 73 00 66 6c 61 67}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

