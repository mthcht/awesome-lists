rule HackTool_Linux_Stowaway_A_2147844753_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/Stowaway.A!MTB"
        threat_id = "2147844753"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "Stowaway"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Stowaway/share" ascii //weight: 10
        $x_10_2 = "Stowaway/agent" ascii //weight: 10
        $x_1_3 = "runtime.injectglist" ascii //weight: 1
        $x_1_4 = "canWriteRecord" ascii //weight: 1
        $x_1_5 = "dirtyLocked" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

