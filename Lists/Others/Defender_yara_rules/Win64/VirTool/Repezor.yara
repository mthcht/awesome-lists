rule VirTool_Win64_Repezor_A_2147686950_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Repezor.A"
        threat_id = "2147686950"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Repezor"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {78 39 30 35 7d 4f 0f 94 c0}  //weight: 2, accuracy: High
        $x_1_2 = "zK!DjyiMDK.%Xq%F3gO9fsnr)B.PrFzJ_*yx,z9" ascii //weight: 1
        $x_1_3 = "Ap2Xum'WuWe%Hde/gO6g!P.'A+cLVIQnUPcebhd" ascii //weight: 1
        $x_1_4 = "0:/plugins/rootkit/binary" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

