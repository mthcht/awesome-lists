rule HackTool_Linux_Dismem_A_2147892400_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/Dismem.A!MTB"
        threat_id = "2147892400"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "Dismem"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd.GrepResult" ascii //weight: 1
        $x_5_2 = "/liamg/dismember/pkg/proc" ascii //weight: 5
        $x_5_3 = "/liamg/dismember/pkg/secrets" ascii //weight: 5
        $x_5_4 = "/liamg/dismember/internal/cmd" ascii //weight: 5
        $x_5_5 = "/liamg/dismember/internal/pkg/debug" ascii //weight: 5
        $x_1_6 = "*proc.Device" ascii //weight: 1
        $x_1_7 = "/mm/transparent_hugepage/hpage_pmd_size" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 3 of ($x_1_*))) or
            ((3 of ($x_5_*))) or
            (all of ($x*))
        )
}

