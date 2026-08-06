rule Trojan_MSIL_Juicypotato_VDB_2147975379_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Juicypotato.VDB!MTB"
        threat_id = "2147975379"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Juicypotato"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "cyberstrike P@ssw0rd!2024 /add" wide //weight: 2
        $x_1_2 = "GodPotato.Program" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

