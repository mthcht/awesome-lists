rule VirTool_Win64_MeterShakti_A_2147967411_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/MeterShakti.A"
        threat_id = "2147967411"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "MeterShakti"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "stdapi_net_tcp_client" ascii //weight: 1
        $x_1_2 = "stdapi_net_tcp_server" ascii //weight: 1
        $x_1_3 = "FIN_WAIT1" ascii //weight: 1
        $x_1_4 = "WinHttpGetIEProxyConfigForCurrentUser" ascii //weight: 1
        $x_1_5 = "\\\\.\\pipe\\%08X" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

