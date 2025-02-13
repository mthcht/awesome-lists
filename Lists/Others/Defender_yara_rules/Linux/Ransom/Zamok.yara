rule Ransom_Linux_Zamok_A_2147903257_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/Zamok.A!MTB"
        threat_id = "2147903257"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "Zamok"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "main.move_to_home" ascii //weight: 1
        $x_1_2 = "zamok" ascii //weight: 1
        $x_1_3 = "main.encrypt_dir" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

