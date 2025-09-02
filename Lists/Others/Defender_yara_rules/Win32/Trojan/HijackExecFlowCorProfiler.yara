rule Trojan_Win32_HijackExecFlowCorProfiler_A_2147951128_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/HijackExecFlowCorProfiler.A!sms"
        threat_id = "2147951128"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "HijackExecFlowCorProfiler"
        severity = "Critical"
        info = "sms: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "COR_ENABLE_PROFILING=1" ascii //weight: 1
        $x_1_2 = "COR_PROFILER={12345678-1234-1234-1234-123456789123}" ascii //weight: 1
        $x_1_3 = "COR_PROFILER_PATH=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

