rule VirTool_Win32_EtherRpcConn_A_2147963485_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/EtherRpcConn.A"
        threat_id = "2147963485"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "EtherRpcConn"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = ",\"method\":\"eth_call\",\"params\":" ascii //weight: 5
        $x_1_2 = {62 63 31 71 [0-16] 62 63 31 70}  //weight: 1, accuracy: Low
        $x_1_3 = {62 69 74 63 6f 69 6e 63 61 73 68 3a 71 [0-16] 62 69 74 63 6f 69 6e 63 61 73 68 3a 70}  //weight: 1, accuracy: Low
        $x_1_4 = {6c 74 63 31 71 00}  //weight: 1, accuracy: High
        $x_1_5 = {63 6f 73 6d 6f 73 31 00}  //weight: 1, accuracy: High
        $x_1_6 = ".binance.org" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

