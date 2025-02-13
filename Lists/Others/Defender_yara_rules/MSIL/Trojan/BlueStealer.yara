rule Trojan_MSIL_BlueStealer_PB_2147845260_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/BlueStealer.PB!MTB"
        threat_id = "2147845260"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "BlueStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {07 72 2a 05 00 70 72 2e 05 00 70 6f ?? ?? 00 0a 0b 73 c3 00 00 0a 0c 16 0d 2b 23 00 07 09 18 6f ?? ?? 00 0a 20 03 02 00 00 28 ?? ?? 00 0a 13 05 08}  //weight: 1, accuracy: Low
        $x_1_2 = "PSO.Properties.Resources" wide //weight: 1
        $x_1_3 = "Xnor" ascii //weight: 1
        $x_1_4 = "fGtH.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

