rule Trojan_MSIL_Urelas_SP_2147843563_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Urelas.SP!MTB"
        threat_id = "2147843563"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Urelas"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {11 06 17 8d 33 00 00 01 25 16 1f 20 9d 6f ?? ?? ?? 0a 13 08 00 11 08 13 09 16 13 0a 38 8a 00 00 00 11 09 11 0a 9a 13 0b 11 0b 72 35 a2 00 70 6f ?? ?? ?? 0a 13 0c 11 0c 2c 6b 00 11 0b 28 ?? ?? ?? 06 13 0d 06 11 0d 6f ?? ?? ?? 0a 2d 0e 11 0d 72 27 a2 00 70 28 ?? ?? ?? 0a}  //weight: 3, accuracy: Low
        $x_1_2 = "runos.exe" wide //weight: 1
        $x_1_3 = "iomDome.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

