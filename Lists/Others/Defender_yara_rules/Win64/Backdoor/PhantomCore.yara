rule Backdoor_Win64_PhantomCore_MK_2147971855_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/PhantomCore.MK!MTB"
        threat_id = "2147971855"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "PhantomCore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "dfxhost.dll" ascii //weight: 10
        $x_5_2 = "/api/clients/report-ssh-status" ascii //weight: 5
        $x_3_3 = "/api/clients/ssh-terminated" ascii //weight: 3
        $x_2_4 = "/api/clients/heartbeat" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

