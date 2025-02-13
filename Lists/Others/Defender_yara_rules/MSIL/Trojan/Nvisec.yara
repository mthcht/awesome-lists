rule Trojan_MSIL_Nvisec_A_2147689357_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nvisec.A"
        threat_id = "2147689357"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nvisec"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "-- Keyloger Activado " ascii //weight: 1
        $x_1_2 = "Resultado Comando" ascii //weight: 1
        $x_1_3 = "key.Screen" ascii //weight: 1
        $x_1_4 = "key.Process" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

