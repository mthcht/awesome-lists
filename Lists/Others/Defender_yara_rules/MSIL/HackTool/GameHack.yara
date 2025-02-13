rule HackTool_MSIL_GameHack_G_2147756318_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MSIL/GameHack.G!MSR"
        threat_id = "2147756318"
        type = "HackTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "GameHack"
        severity = "High"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Confuser" ascii //weight: 2
        $x_2_2 = "SazInjector.exe" ascii //weight: 2
        $x_1_3 = "SazInjector.Resources.resources" ascii //weight: 1
        $x_1_4 = "Assembly System.Reflection" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

