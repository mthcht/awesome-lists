rule Ransom_Linux_Vect_AMTB_2147968053_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/Vect!AMTB"
        threat_id = "2147968053"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "Vect"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 14 01 49 8d ?? ?? ?? ff ff 83 f2 ?? 42 88 94 ?? ?? ?? ff ff 48 83 c0 01 48 83 f8 ?? 75 e0}  //weight: 1, accuracy: Low
        $x_1_2 = "Encryption complete" ascii //weight: 1
        $x_1_3 = "Initializing encryption engine" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

