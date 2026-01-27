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

rule Trojan_Win64_Splinter_MS1_2147961764_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Splinter.MS1!dha"
        threat_id = "2147961764"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Splinter"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Implant graceful shutdown" ascii //weight: 10
        $x_10_2 = "struct ImplantId" ascii //weight: 10
        $x_10_3 = "struct ImplantConfig" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Splinter_MS2_2147961765_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Splinter.MS2!dha"
        threat_id = "2147961765"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Splinter"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Failed to initialize implant" ascii //weight: 1
        $x_1_2 = "splinter_core\\c2_client\\src\\lib.rs" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

