rule Ransom_MSIL_Lockbit_SNA_2147964159_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Lockbit.SNA!MTB"
        threat_id = "2147964159"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lockbit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {1d 8d 09 00 00 01 25 16 20 72 42 00 00 28 c7 00 00 06 a2 25 17 12 00 7e 2a 01 00 04 28 9e 03 00 06 a2 25 18 20 5c 42 00 00 28 c7 00 00 06 a2 25 19 12 00 7e 2b 01 00 04 28 9e 03 00 06 a2 25 1a 20 62 42 00 00 28 87 01 00 06 a2 25 1b 02 a2 25 1c 20 6a 42 00 00 28 87 01 00 06 a2 7e d3 00 00 04 28 c6 02 00 06 13 01}  //weight: 4, accuracy: High
        $x_2_2 = "$ce785c71-79ac-4231-917c-040b58f94cb5" ascii //weight: 2
        $x_1_3 = "Debugger Detected" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

