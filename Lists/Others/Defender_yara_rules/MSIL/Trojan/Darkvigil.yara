rule Trojan_MSIL_Darkvigil_NWA_2147969002_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Darkvigil.NWA!MTB"
        threat_id = "2147969002"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Darkvigil"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {03 09 58 91 05 61 d2 9c 00 09 17 58 0d}  //weight: 2, accuracy: High
        $x_1_2 = {02 08 02 08 91 03 61 d2 9c 00 08 17 58 0c}  //weight: 1, accuracy: High
        $x_1_3 = "costura.touchsocket.dmtp.dll.compressed" ascii //weight: 1
        $x_1_4 = "Monitor_Enter2" ascii //weight: 1
        $x_1_5 = "ContainsKey" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

