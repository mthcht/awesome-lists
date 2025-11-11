rule Trojan_MSIL_DelDest_DA_2147957181_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DelDest.DA!MTB"
        threat_id = "2147957181"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DelDest"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0a 0b 07 2c 2e 00 73 [0-3] 0a 0c 08 17 1f 64 6f [0-3] 0a 0d 09 1f 50 fe 02 13 04 11 04 2c 11 00 28 [0-3] 0a 13 05 11 05 6f [0-3] 0a 00 00 00 02 13 06 2b 00 11 06 2a}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DelDest_DB_2147957182_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DelDest.DB!MTB"
        threat_id = "2147957182"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DelDest"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "shanhai" ascii //weight: 20
        $x_1_2 = "BYDScreenAndMes20221221\\DbRepository" ascii //weight: 1
        $x_1_3 = "GetLogRepository" ascii //weight: 1
        $x_20_4 = "user id=sa;password=123456" ascii //weight: 20
        $x_1_5 = "initial catalog=BYDSA_CS1" ascii //weight: 1
        $x_1_6 = "data source=127.0.0.1\\JC" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 2 of ($x_1_*))) or
            ((2 of ($x_20_*))) or
            (all of ($x*))
        )
}

