rule Ransom_Linux_Sarcoma_A_2147940024_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/Sarcoma.A!MTB"
        threat_id = "2147940024"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "Sarcoma"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FAIL_STATE_NOTIFICATION.pdf" ascii //weight: 1
        $x_1_2 = "vim-cmd vmsvc/snapshot.removeall" ascii //weight: 1
        $x_1_3 = {44 89 d0 44 0f b6 cb 44 89 d9 c1 e8 18 c1 e9 10 44 8b 06 0f b6 d0 46 33 04 8d 80 bc 42 00 48 89 f8 44 0f b6 c9 44 33 04 95 80 b0 42 00 41 0f b6 ca 0f b6 d4 44 89 d8 46 33 04 8d 80 b4 42 00 c1 e8 18 44 8b 4e 04 44 33 0c 8d 80 bc 42 00 89 f9 44 33 04 95 80 b8 42 00 0f b6 d0 c1 e9 10 44 33 0c 95 80 b0 42 00 0f b6 d7 0f b6 c1 41 0f b6 cb c1 eb 10 44 33 0c 85 80 b4 42 00 89 f8 c1 e8 18 44 33 0c 95 80 b8 42 00 8b 56 08 33 14 8d 80 bc 42 00 0f b6 c8 0f b6 c3 33 14 8d 80 b0 42 00 4c 89 d1 c1 eb 08 33 14 85 80 b4 42 00 0f b6 c5 41 c1 ea 10 33 14 85 80 b8 42 00 40 0f b6 c7 8b 4e 0c 33 0c 85 80 bc 42 00 0f b6 c3 41 0f b6 fa 33 0c 85 80 b0 42 00 4c 89 db 33 0c bd 80 b4 42 00 0f b6 c7 33 0c 85 80 b8 42 00 44 89 c7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

