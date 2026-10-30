rule Ransom_MacOS_HeartBreaker_AMTB_2147981243_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MacOS/HeartBreaker!AMTB"
        threat_id = "2147981243"
        type = "Ransom"
        platform = "MacOS: "
        family = "HeartBreaker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "heartbreakerEncrypting file" ascii //weight: 2
        $x_2_2 = ".heartbreaker" ascii //weight: 2
        $x_1_3 = "sudo ./heartbreaker" ascii //weight: 1
        $x_1_4 = "fileHEARTBREAKER WARNING!" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

