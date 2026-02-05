rule Trojan_VBA_Runner_GPAX_2147962481_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:VBA/Runner.GPAX!MTB"
        threat_id = "2147962481"
        type = "Trojan"
        platform = "VBA: Visual Basic for Applications scripts"
        family = "Runner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "Run(Chr(34) & exePath & Chr(34), 1, True" ascii //weight: 5
        $x_2_2 = "library /nologo /unsafe" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

