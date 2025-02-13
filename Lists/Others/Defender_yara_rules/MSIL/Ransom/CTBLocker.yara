rule Ransom_MSIL_CTBLocker_CT_2147845388_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/CTBLocker.CT!MTB"
        threat_id = "2147845388"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CTBLocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {06 20 84 02 00 00 58 0a 06 20 cf 01 00 00 58 0a 04 03 5e 0c 06 20 e6 03 00 00 58 0a 06 20 9c 02 00 00 58 0a 02 08 91 0d 06 20 e6 01 00 00 58 0a 06 20 44 01 00 00 58 0a 02 08 02 07 17 59 91 9c 06 20 61 02 00 00 58 0a 06 20 72 01 00 00 58 0a 02 07 17 59 09 9c 06 20 55 01 00 00 58 0a 06 20 54 03 00 00 58 0a 04 1f 19 64 04 1d 62 60 10 02 06 20 cd 00 00 00 58 0a 06 20 d0 01 00 00 58}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

