rule Ransom_Win64_BlackWidow_YBG_2147961274_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/BlackWidow.YBG!MTB"
        threat_id = "2147961274"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "BlackWidow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "BLACK WIDOW" ascii //weight: 1
        $x_1_2 = "servers are encrypted" ascii //weight: 1
        $x_1_3 = "bitcoin" ascii //weight: 1
        $x_1_4 = "You have to pay" ascii //weight: 1
        $x_1_5 = "Decryption Key" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

