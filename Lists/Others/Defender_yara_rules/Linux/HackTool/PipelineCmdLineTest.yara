rule HackTool_Linux_PipelineCmdLineTest_A_2147962400_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/PipelineCmdLineTest.A"
        threat_id = "2147962400"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "PipelineCmdLineTest"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "wdlinux_pipeline_stage1_e2e" wide //weight: 10
        $x_10_2 = "wdlinux_pipeline_stage2_e2e" wide //weight: 10
        $x_10_3 = "wdlinux_pipeline_stage3_e2e" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

