rule Ransom_Linux_Gonnacry_C_2147901040_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/Gonnacry.C!MTB"
        threat_id = "2147901040"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "Gonnacry"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "Sup brother, all your files below have been encrypted" ascii //weight: 5
        $x_5_2 = "GonnaCry" ascii //weight: 5
        $x_1_3 = "KEY = %s IV = %s PATH = %s" ascii //weight: 1
        $x_1_4 = "zip backup" ascii //weight: 1
        $x_1_5 = "encrypt_files" ascii //weight: 1
        $x_1_6 = "exfiltrate_data" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 3 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

