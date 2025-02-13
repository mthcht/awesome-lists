rule Trojan_MSIL_Guloader_KAE_2147926439_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Guloader.KAE!MTB"
        threat_id = "2147926439"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Guloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "dissentieringernes\\Bilassistenters" ascii //weight: 1
        $x_1_2 = "Urbacity\\Uninstall\\deltransformations" ascii //weight: 1
        $x_1_3 = "maskinfikseret.ini" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

