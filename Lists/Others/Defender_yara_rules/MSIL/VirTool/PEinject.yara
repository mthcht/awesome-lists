rule VirTool_MSIL_PEinject_GA_2147811467_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/PEinject.GA!MTB"
        threat_id = "2147811467"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PEinject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\RegAsm.exe" wide //weight: 20
        $x_10_2 = "https://github.com/Gaganin1212/bugtik/raw/main/" wide //weight: 10
        $x_10_3 = "https://github.com/Gaganin1212/sosalka/raw/main/" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 1 of ($x_10_*))) or
            (all of ($x*))
        )
}

