rule Ransom_MSIL_Lazy_SN_2147964160_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Lazy.SN!MTB"
        threat_id = "2147964160"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {45 02 00 00 00 2f 00 00 00 05 00 00 00 38 2a 00 00 00 1d 28 2a 00 00 0a 20 22 27 00 00 28 89 00 00 06 28 e0 00 00 06 20 00 00 00 00 28 8d 00 00 06 3a ca ff ff ff}  //weight: 4, accuracy: High
        $x_2_2 = "$ce785c71-79ac-4231-917c-040b58f94cb5" ascii //weight: 2
        $x_1_3 = "Debugger Detected" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

