rule Trojan_MSIL_UACBypassExp_AU_2147896150_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/UACBypassExp.AU!MTB"
        threat_id = "2147896150"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "UACBypassExp"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {08 09 9a 13 04 00 00 06 11 04 72 2f 00 00 70 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 13 05 11 05 72 49 00 00 70 72 4b 00 00 70 6f ?? ?? ?? 0a 00 00 de 1a 13 06 00 11 04 11 06}  //weight: 2, accuracy: Low
        $x_1_2 = "shell\\open\\command" wide //weight: 1
        $x_1_3 = "\\ProgramData\\dame.exe" wide //weight: 1
        $x_1_4 = "Screen_Shot_2020-07-27_at_3.12.22_PM" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

