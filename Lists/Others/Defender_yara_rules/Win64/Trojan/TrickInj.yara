rule Trojan_Win64_TrickInj_A_2147766707_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/TrickInj.A!MTB"
        threat_id = "2147766707"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "TrickInj"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "inj_64.dll" ascii //weight: 1
        $x_1_2 = "[INIT] Inj = %u" ascii //weight: 1
        $x_1_3 = "[INIT] BC = %u" ascii //weight: 1
        $x_1_4 = "[INIT] Proxy = %u" ascii //weight: 1
        $x_1_5 = "#pgid#" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

