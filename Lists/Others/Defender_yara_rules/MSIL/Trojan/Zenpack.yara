rule Trojan_MSIL_Zenpack_KAA_2147921803_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zenpack.KAA!MTB"
        threat_id = "2147921803"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zenpack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {18 58 49 11 04 46 61 52 16 28 ?? 00 00 06 26 06 17 58 0a 06}  //weight: 1, accuracy: Low
        $x_1_2 = "VirtualProtect" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

