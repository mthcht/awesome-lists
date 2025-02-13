rule VirTool_MSIL_DjangoRein_C_2147815332_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/DjangoRein.C!MTB"
        threat_id = "2147815332"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DjangoRein"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RecordSOA" ascii //weight: 1
        $x_1_2 = "TXTDNAME" ascii //weight: 1
        $x_1_3 = "command" ascii //weight: 1
        $x_1_4 = "upload" ascii //weight: 1
        $x_1_5 = "posh_in_mem" ascii //weight: 1
        $x_1_6 = "socks" ascii //weight: 1
        $x_1_7 = "interactive" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

