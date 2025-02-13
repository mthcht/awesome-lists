rule VirTool_Win64_OfsBuilz_B_2147895620_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/OfsBuilz.B!MTB"
        threat_id = "2147895620"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "OfsBuilz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "OffensivePipeline" ascii //weight: 1
        $x_1_2 = "OffensivePipeline.dll" ascii //weight: 1
        $x_1_3 = "github.com/aetsu" ascii //weight: 1
        $x_1_4 = "socket" ascii //weight: 1
        $x_1_5 = "Shell" ascii //weight: 1
        $x_1_6 = "requestedPrivileges" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

