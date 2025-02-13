rule Trojan_MSIL_ReverseRat_CCBH_2147891441_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ReverseRat.CCBH!MTB"
        threat_id = "2147891441"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ReverseRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {06 07 02 07 91 03 07 03 8e 69 5d 91 61 d2 9c 07 17 58 0b 07 02 8e 69 32 e7}  //weight: 1, accuracy: High
        $x_1_2 = "AES_Decrypt" ascii //weight: 1
        $x_1_3 = "XOR_Decrypt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

