rule Worm_MSIL_Nerty_B_2147652278_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:MSIL/Nerty.B"
        threat_id = "2147652278"
        type = "Worm"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nerty"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FloodThreads" ascii //weight: 1
        $x_1_2 = {2e 73 70 72 65 61 64 65 72 73 00 69 6d 00 6d 73 6e 00 61 69 6d}  //weight: 1, accuracy: High
        $x_1_3 = {25 4d 00 65 00 72 00 71 00 79 00 5b 00 25 00 75 00 73 00 65 00 72 00 25 00 40 00 25 00 70 00 63 00 25 00 5d 00}  //weight: 1, accuracy: High
        $x_1_4 = {31 7b 00 48 00 61 00 76 00 65 00 41 00 4e 00 69 00 63 00 65 00 44 00 61 00 79 00 2d 00 54 00 65 00 61 00 6d 00 4d 00 65 00 72 00 71 00 79 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

