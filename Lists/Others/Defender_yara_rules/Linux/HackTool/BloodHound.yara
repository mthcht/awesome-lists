rule HackTool_Linux_BloodHound_A_2147832770_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/BloodHound.A!MTB"
        threat_id = "2147832770"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "BloodHound"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/bloodhoundad/azurehound" ascii //weight: 1
        $x_1_2 = "IfV12K8xAKAnZqdXVzCZ+TOjboZ2keLg81eXfW3O+oY=" ascii //weight: 1
        $x_1_3 = "fY5BOSpyZCqRo5OhCuC+XN+r/bBCmeuuJtjz+bCNIf8=" ascii //weight: 1
        $x_1_4 = "tjENF6MfZAg8e4ZmZTeWaWiT2vXtsoO6+iuOjFhECwM=" ascii //weight: 1
        $x_1_5 = "0Anlzjpi4vEasTeNFn2mLJgTSwt0+6sfsiTG8qcWGx4=" ascii //weight: 1
        $x_1_6 = "D8xgwECY7CYvx+Y2n4sBz93Jn9JRvxdiyyo8CTfuKaY=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

