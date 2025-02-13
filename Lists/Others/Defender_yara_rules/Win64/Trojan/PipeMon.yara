rule Trojan_Win64_PipeMon_H_2147762205_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/PipeMon.H!MTB"
        threat_id = "2147762205"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "PipeMon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "spool\\prtprocs\\x64" wide //weight: 10
        $x_1_2 = "Failed to inject the DLL" ascii //weight: 1
        $x_1_3 = "%s inject %d failed %d" ascii //weight: 1
        $x_1_4 = "Injection FAILED!" wide //weight: 1
        $x_1_5 = "inject Pid :%d return:%d" ascii //weight: 1
        $x_1_6 = "WriteProcessMemory FAILED!" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

