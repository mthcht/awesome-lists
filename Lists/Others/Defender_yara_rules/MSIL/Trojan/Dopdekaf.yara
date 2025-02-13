rule Trojan_MSIL_Dopdekaf_A_2147829189_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Dopdekaf.A!MTB"
        threat_id = "2147829189"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Dopdekaf"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {01 57 95 02 28 09 02 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 21 00 00 00 05 00 00 00 2f 01 00 00 1e}  //weight: 4, accuracy: High
        $x_1_2 = "HandleProcessCorruptedStateExceptionsAttribute" ascii //weight: 1
        $x_1_3 = "FileAccess" ascii //weight: 1
        $x_1_4 = "FileShare" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

