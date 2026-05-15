rule Backdoor_Win64_PulsarRat_MKA_2147969424_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/PulsarRat.MKA!MTB"
        threat_id = "2147969424"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "PulsarRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "[svcs] SERVICE_CONTROL_SHUTDOWN" ascii //weight: 10
        $x_5_2 = "[svcs] SERVICE_CONTROL_PAUSE" ascii //weight: 5
        $x_3_3 = "[svcs] SERVICE_CONTROL_CONTINUE" ascii //weight: 3
        $x_2_4 = "[svcs] DLL_PROCESS_ATTACH" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

