rule Ransom_Linux_Phalcon_A_2147959706_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/Phalcon.A!MTB"
        threat_id = "2147959706"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "Phalcon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Phalcon" ascii //weight: 1
        $x_1_2 = "/tmp/stopall.sh" ascii //weight: 1
        $x_1_3 = "neutrino_restore.txt" ascii //weight: 1
        $x_1_4 = "-path /path/to/encrypt" ascii //weight: 1
        $x_1_5 = "drop_note" ascii //weight: 1
        $x_1_6 = "encrypt_file" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

