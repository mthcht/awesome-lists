rule VirTool_Win32_JsonRpcEthCall_A_2147978796_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/JsonRpcEthCall.A"
        threat_id = "2147978796"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "JsonRpcEthCall"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {22 69 64 22 3a [0-2] 31 2c}  //weight: 1, accuracy: Low
        $x_1_2 = {22 6a 73 6f 6e 72 70 63 22 3a [0-2] 22 32 2e 30 22 2c}  //weight: 1, accuracy: Low
        $x_1_3 = {22 6d 65 74 68 6f 64 22 3a [0-2] 22 65 74 68 5f 63 61 6c 6c 22 2c}  //weight: 1, accuracy: Low
        $x_1_4 = {22 70 61 72 61 6d 73 22 3a [0-2] 5b 7b 22 74 6f 22 3a [0-2] 22 30 78}  //weight: 1, accuracy: Low
        $x_1_5 = {22 64 61 74 61 22 3a [0-2] 22 30 78}  //weight: 1, accuracy: Low
        $x_1_6 = "\"latest\"]}" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

