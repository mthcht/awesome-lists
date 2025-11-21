rule Ransom_Win64_Lockfile_CH_2147958012_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Lockfile.CH!MTB"
        threat_id = "2147958012"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Lockfile"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "amsi_bypass.rs" ascii //weight: 2
        $x_2_2 = "credentials.rs" ascii //weight: 2
        $x_2_3 = "persistence.rs" ascii //weight: 2
        $x_2_4 = "anti_analysis.rs" ascii //weight: 2
        $x_2_5 = "dns_tunneling.rs" ascii //weight: 2
        $x_2_6 = "analysis_tool_detected" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

