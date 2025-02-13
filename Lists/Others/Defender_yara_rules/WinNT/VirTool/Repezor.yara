rule VirTool_WinNT_Repezor_A_2147686949_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Repezor.A"
        threat_id = "2147686949"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Repezor"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {81 79 08 90 35 7d 4f 75 06 b0 01}  //weight: 2, accuracy: High
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

