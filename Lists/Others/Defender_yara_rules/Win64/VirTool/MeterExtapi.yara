rule VirTool_Win64_MeterExtapi_A_2147967404_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/MeterExtapi.A"
        threat_id = "2147967404"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "MeterExtapi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SYSTEM\\CurrentControlSet\\Control\\Lsa" ascii //weight: 1
        $x_1_2 = "EnumServicesStatusExA" ascii //weight: 1
        $x_1_3 = "PageantRequest%08x" ascii //weight: 1
        $x_1_4 = "JetBeginSessionA" ascii //weight: 1
        $x_1_5 = "JetEndSession" ascii //weight: 1
        $x_1_6 = "GlobalLock" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

