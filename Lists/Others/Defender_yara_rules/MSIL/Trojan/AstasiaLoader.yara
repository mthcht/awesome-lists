rule Trojan_MSIL_AstasiaLoader_PA_2147853113_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AstasiaLoader.PA!MTB"
        threat_id = "2147853113"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AstasiaLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\infected.exe" wide //weight: 1
        $x_1_2 = "AstasiaLoader" wide //weight: 1
        $x_3_3 = {07 1f 1c 28 ?? 00 00 0a 72 ?? ?? ?? ?? 28 ?? 00 00 0a 6f ?? 00 00 0a 20 d0 07 00 00 28 ?? 00 00 0a 1f 1c 28 ?? 00 00 0a 72 ?? ?? ?? ?? 28}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

