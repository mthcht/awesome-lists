rule HackTool_Linux_MerlinAgentExec_A_2147775257_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/MerlinAgentExec.A!!MerlinAgentExec.A"
        threat_id = "2147775257"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "MerlinAgentExec"
        severity = "High"
        info = "MerlinAgentExec: an internal category used to refer to some threats"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/usr/bin/lesspipe.sh" ascii //weight: 1
        $x_1_2 = "github.com/Ne0nd0g/merlin/pkg/messages.Module" ascii //weight: 1
        $x_1_3 = "merlin/pkg/messages.KeyExchange" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

