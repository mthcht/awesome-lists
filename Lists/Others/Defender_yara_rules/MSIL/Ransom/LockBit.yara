rule Ransom_MSIL_LockBit_MK_2147947645_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/LockBit.MK!MTB"
        threat_id = "2147947645"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LockBit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "35"
        strings_accuracy = "High"
    strings:
        $x_35_1 = {72 5d 00 00 70 11 04 28 1d 00 00 0a 73 1e 00 00 0a 13 0b 11 0b 73 1f 00 00 0a 13 0c 11 0c 72 5d 00 00 70 6f 20 00 00 0a 11 0c 16 6f 21 00 00 0a 11 0c}  //weight: 35, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

