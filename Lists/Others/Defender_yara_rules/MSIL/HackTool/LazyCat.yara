rule HackTool_MSIL_LazyCat_YA_2147733653_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MSIL/LazyCat.YA!MTB"
        threat_id = "2147733653"
        type = "HackTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LazyCat"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "LazyCat.dll" wide //weight: 1
        $x_1_2 = "VirtualSite: {0}, Address: {1:X16}, Name: {2}, Handle: {3:X16}, LogPath: {4}" wide //weight: 1
        $x_1_3 = "LazyCat.local_privilege_escalation.rotten_potato" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

