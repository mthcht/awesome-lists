rule Backdoor_MacOS_PostMerlin_2147745406_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MacOS/PostMerlin!MTB"
        threat_id = "2147745406"
        type = "Backdoor"
        platform = "MacOS: "
        family = "PostMerlin"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "github.com/Ne0nd0g" ascii //weight: 2
        $x_1_2 = "ExecuteShellcode" ascii //weight: 1
        $x_1_3 = "merlin/pkg/agent." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

