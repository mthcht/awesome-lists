rule MonitoringTool_MSIL_Emissary_204967_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:MSIL/Emissary"
        threat_id = "204967"
        type = "MonitoringTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Emissary"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Emissary Keylogger" wide //weight: 10
        $x_1_2 = "chkStealers" wide //weight: 1
        $x_1_3 = "chkAnti" wide //weight: 1
        $x_1_4 = "chkStartup" wide //weight: 1
        $x_1_5 = "chkscreenshot" wide //weight: 1
        $x_1_6 = "chkdownloader" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule MonitoringTool_MSIL_Emissary_204967_1
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:MSIL/Emissary"
        threat_id = "204967"
        type = "MonitoringTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Emissary"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_10_1 = ": Emissary Logs" wide //weight: 10
        $x_1_2 = "DisableRegistryTools" wide //weight: 1
        $x_1_3 = "127.0.0.1 www.virustotal.com" wide //weight: 1
        $x_1_4 = "\\Screenshot" wide //weight: 1
        $x_1_5 = "keyscrambler" wide //weight: 1
        $x_1_6 = "ollydbg" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

