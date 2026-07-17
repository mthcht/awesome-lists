rule Ransom_Win64_Dementor_YDQ_2147973540_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Dementor.YDQ!MTB"
        threat_id = "2147973540"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Dementor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "recycle_binransom" ascii //weight: 1
        $x_1_2 = "ransom_network_shares" ascii //weight: 1
        $x_1_3 = "remove_recycle_bin" ascii //weight: 1
        $x_1_4 = "get decryption software" ascii //weight: 1
        $x_1_5 = "after your payment" ascii //weight: 1
        $x_1_6 = "publicly available " ascii //weight: 1
        $x_1_7 = "decrypt it for free " ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

