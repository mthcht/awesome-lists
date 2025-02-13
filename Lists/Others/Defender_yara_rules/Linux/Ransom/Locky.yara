rule Ransom_Linux_Locky_A_2147930783_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/Locky.A!MTB"
        threat_id = "2147930783"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "Locky"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "encrypt_file" ascii //weight: 1
        $x_1_2 = ".osiris" ascii //weight: 1
        $x_1_3 = "encrypt_block" ascii //weight: 1
        $x_1_4 = "byte_to_xor =" ascii //weight: 1
        $x_1_5 = "Rw by [afjoseph]" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

