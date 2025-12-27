rule Trojan_MSIL_EtwHook_GVA_2147947417_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/EtwHook.GVA!MTB"
        threat_id = "2147947417"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "EtwHook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {72 b7 0d 00 70 28 3d 00 00 06 72 21 15 00 70 28 3c 00 00 06 0b 07 02 8e 69 6a 28 66 00 00 0a 1f 40 12 00 28 3e 00 00 06 26 02 16 07 02 8e 69 28 32 00 00 0a de 0d 26 72 3d 15 00 70 28 1b 00 00 0a de 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

