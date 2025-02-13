rule VirTool_Win64_TokenManipulator_A_2147907882_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/TokenManipulator.A"
        threat_id = "2147907882"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "TokenManipulator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "list_tokens" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

