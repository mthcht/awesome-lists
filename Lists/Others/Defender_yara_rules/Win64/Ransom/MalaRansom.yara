rule Ransom_Win64_MalaRansom_YBE_2147963571_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/MalaRansom.YBE!MTB"
        threat_id = "2147963571"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "MalaRansom"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Mala Ransom" ascii //weight: 1
        $x_1_2 = "you do not have to pay us" ascii //weight: 1
        $x_1_3 = "decryption" ascii //weight: 1
        $x_1_4 = "encrypted" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

