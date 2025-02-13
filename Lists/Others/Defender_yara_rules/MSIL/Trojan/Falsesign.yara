rule Trojan_MSIL_Falsesign_RPW_2147824246_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Falsesign.RPW!MTB"
        threat_id = "2147824246"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Falsesign"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {32 00 34 00 68 00 72 00 73 00 74 00 72 00 61 00 63 00 6b 00 2e 00 63 00 6f 00 6d 00 2f 00 6c 00 6f 00 61 00 64 00 65 00 72 00 2f 00 75 00 70 00 6c 00 6f 00 61 00 64 00 73 00 2f 00 [0-48] 2e 00 62 00 6d 00 70 00}  //weight: 1, accuracy: Low
        $x_1_2 = "powershell" wide //weight: 1
        $x_1_3 = "-enc UwB0AEEAcgB0AC0AUwBsAEUAZQBQACAALQBzACAAMgAwAA==" wide //weight: 1
        $x_1_4 = "WebClient" ascii //weight: 1
        $x_1_5 = "ToArray" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

