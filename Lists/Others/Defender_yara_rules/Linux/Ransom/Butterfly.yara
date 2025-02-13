rule Ransom_Linux_Butterfly_A_2147906487_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/Butterfly.A!MTB"
        threat_id = "2147906487"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "Butterfly"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = ".bfly" ascii //weight: 1
        $x_1_2 = {74 74 70 3a 2f 2f [0-86] 2e 6f 6e 69 6f 6e}  //weight: 1, accuracy: Low
        $x_1_3 = "--encrypt /home/butterfly/data/" ascii //weight: 1
        $x_1_4 = "--decrypt /home/butterfly/data/ --tor" ascii //weight: 1
        $x_1_5 = "--decrypt /home/butterfly/data/ --key /home/butterfly/butterfly/masterkeys/SPrivateRSA.pem" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

