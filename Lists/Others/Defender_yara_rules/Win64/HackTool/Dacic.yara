rule HackTool_Win64_Dacic_AHA_2147969270_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/Dacic.AHA!MTB"
        threat_id = "2147969270"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Dacic"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "60"
        strings_accuracy = "High"
    strings:
        $x_30_1 = "Created by: K3rnelPan1c5750 and Ixeoz.Axiom" ascii //weight: 30
        $x_20_2 = "sdiscord_utils.node" ascii //weight: 20
        $x_10_3 = "RawInputPatchDelayMs" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

