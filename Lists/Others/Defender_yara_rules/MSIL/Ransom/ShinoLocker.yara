rule Ransom_MSIL_ShinoLocker_KS_2147896071_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/ShinoLocker.KS!MTB"
        threat_id = "2147896071"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ShinoLocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {06 72 a0 61 00 70 28 51 00 00 0a 72 a0 61 00 70 28 52 00 00 0a 6b 5a 22 00 00 80 3f 58 28 53 00 00 0a 6c 28 54 00 00 0a b7 17 28 55 00 00 0a 28 3c 00 00 0a 0a 08 17 d6 0c 08 07 31 c3}  //weight: 10, accuracy: High
        $x_3_2 = ".shino" ascii //weight: 3
        $x_3_3 = "get_StartInfo" ascii //weight: 3
        $x_3_4 = "get_ExecutablePath" ascii //weight: 3
        $x_3_5 = "ShinoLocker" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

