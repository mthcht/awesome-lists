rule Trojan_MSIL_Sunilla_A_2147742341_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Sunilla.A!dha"
        threat_id = "2147742341"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Sunilla"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = "3513ca6f-e392-40f3-965b-9d4af7fd4040" ascii //weight: 5
        $x_2_2 = "ChaperoneServiceMonitor" ascii //weight: 2
        $x_2_3 = "MaintPol.dll" ascii //weight: 2
        $x_2_4 = {50 00 72 00 6f 00 64 00 75 00 63 00 74 00 4e 00 61 00 6d 00 65 00 [0-5] 4d 00 61 00 69 00 6e 00 74 00 65 00 6e 00 61 00 6e 00 63 00 65 00 20 00 50 00 6f 00 6c 00 69 00 63 00 79 00}  //weight: 2, accuracy: Low
        $x_1_5 = "CheckRemoveDate" ascii //weight: 1
        $x_1_6 = "SetServiceRegistry" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            ((1 of ($x_5_*))) or
            (all of ($x*))
        )
}

