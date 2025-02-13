rule TrojanSpy_AndroidOS_Seafko_A_2147753729_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Seafko.A!MTB"
        threat_id = "2147753729"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Seafko"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Lcom/sas/seafkoagent/seafkoagent" ascii //weight: 2
        $x_1_2 = "content://call_log/calls" ascii //weight: 1
        $x_1_3 = "Terminating all Agent services" ascii //weight: 1
        $x_1_4 = "SEAFKO ATTACK SYSTEM IS IN CONTROL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

