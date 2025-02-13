rule Trojan_Win64_Splinter_MV_2147853149_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Splinter.MV!MSR"
        threat_id = "2147853149"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Splinter"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "0hchanLeafinterfacemSpanDeadpanicwaitpclmulqdqpreemptedprofBlockrwxrwxrwxstackpooltracebackwbufSpans0123456789Bad" ascii //weight: 1
        $x_1_2 = "VirtualWSARecvWSASendabortedanalyisanswersavx512fcharsetchunkedconnectconsolecpuprofderivedexpiresflattenfloat32float64forcegcfromstrhttp" ascii //weight: 1
        $x_1_3 = "osxsavepdh.dllprocessrefererrefreshresponereverserunningsandboxserial" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

