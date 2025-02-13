rule Trojan_MSIL_SpideyBot_A_2147824424_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpideyBot.A!MTB"
        threat_id = "2147824424"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpideyBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 0c 25 72 ?? ?? ?? 70 07 72 ?? ?? ?? 70 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 25 72 0e 01}  //weight: 1, accuracy: Low
        $x_1_2 = {07 08 9a 28 ?? ?? ?? 0a 72 ?? ?? ?? 70 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 0d}  //weight: 1, accuracy: Low
        $x_1_3 = {0a 74 19 00 ?? 01 13 ?? 06 11 ?? 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 09 6f ?? ?? ?? 0a 2d de}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

