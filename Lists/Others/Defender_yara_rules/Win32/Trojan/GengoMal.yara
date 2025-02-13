rule Trojan_Win32_GengoMal_A_2147769523_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GengoMal.A!MTB"
        threat_id = "2147769523"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GengoMal"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "6m3WeYhXAStZ0SgTGENQ/tN9JajvVfd9tD624GoYu/1e3mup3hW_ZAv8-B7YXM/dki6BQ89YLt3EH1PhNxp" ascii //weight: 1
        $x_1_2 = "Go build ID" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

