rule Ransom_Linux_BlackBasta_A_2147820382_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/BlackBasta.A!MTB"
        threat_id = "2147820382"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "BlackBasta"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4a 03 04 c2 4e 8b 0c c6 49 89 c2 0f 92 c0 45 31 db 4d 39 d1 0f b6 c0 41 0f 92 c3 4d 29 d1 4e 89 0c c7 49 83 c0 01 4c 01 d8 49 39 c8}  //weight: 1, accuracy: High
        $x_1_2 = {4c 89 f2 48 33 14 f7 4c 89 d1 4c 01 e2 41 0f 92 c4 49 33 0c f3 45 0f b6 e4 4c 01 e9 41 0f 92 c5 48 31 ca 4c 31 c2 45 0f b6 ed 48 01 da 0f 92 c3 48 89 14 f0 48 83 c6 01 48 39 f5 0f b6 db}  //weight: 1, accuracy: High
        $x_1_3 = {4a 8b 0c de 49 89 c9 89 c9 49 c1 e9 20 49 89 c8 4c 0f af c5 4d 89 ca 4c 0f af d5 49 0f af cc 4c 89 c3 45 89 c0 48 c1 eb 20 49 01 c0 4d 0f af cc 4c 01 d1 48 01 d9 49 89 cf 49 c1 e7 20 4d 01 f8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Linux_BlackBasta_B_2147847809_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/BlackBasta.B!MTB"
        threat_id = "2147847809"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "BlackBasta"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "instructions_read_me.txt" ascii //weight: 2
        $x_2_2 = "-disablewhitelist" ascii //weight: 2
        $x_2_3 = "ofijweiuhuewhcsaxs.mutex" ascii //weight: 2
        $x_1_4 = "-killesxi" ascii //weight: 1
        $x_1_5 = "export processIds=$(esxcli vm process list" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

