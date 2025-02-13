rule Worm_MSIL_Futoo_A_2147630804_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:MSIL/Futoo.A"
        threat_id = "2147630804"
        type = "Worm"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Futoo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {52 53 44 53 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 3a 5c [0-192] 57 6f 72 6d 79 5c 57 6f 72 6d 79 5c 6f 62 6a 5c [0-16] 5c 73 76 63 68 6f 73 74 2e 70 64 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

