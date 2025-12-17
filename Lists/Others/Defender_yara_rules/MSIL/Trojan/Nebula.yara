rule Trojan_MSIL_Nebula_NN_2147959635_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nebula.NN!MTB"
        threat_id = "2147959635"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nebula"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {2d 04 14 0d de 2c 07 6f 9c 00 00 0a d4 8d 3d 00 00 01 0c 07 08 16 08 8e 69 6f 9d 00 00 0a 26 08 28 9e 00 00 0a 0d}  //weight: 2, accuracy: High
        $x_1_2 = "NebulaStealer.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

