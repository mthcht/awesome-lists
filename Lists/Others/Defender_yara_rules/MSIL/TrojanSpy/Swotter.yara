rule TrojanSpy_MSIL_Swotter_PSYW_2147831351_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Swotter.PSYW!MTB"
        threat_id = "2147831351"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Swotter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 25 6f 15 [0-3] 0a 06 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 06 6f ?? ?? ?? 0a 06 6f ?? ?? ?? 0a 0b dd 03 00 00 00 26 de b9}  //weight: 1, accuracy: Low
        $x_1_2 = {0a 0c 06 08 6f ?? ?? ?? 0a 06 18 6f ?? ?? ?? 0a 02 0d 06 6f ?? ?? ?? 0a 09 16 09 8e 69 6f ?? ?? ?? 0a 13 04 dd 1a}  //weight: 1, accuracy: Low
        $x_1_3 = {0a 16 fe 02 39 ?? ?? ?? 00 06 72 ?? ?? ?? 70 6f ?? ?? ?? 0a 72 ?? ?? ?? 70 6f ?? ?? ?? 0a 0b 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 6f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

