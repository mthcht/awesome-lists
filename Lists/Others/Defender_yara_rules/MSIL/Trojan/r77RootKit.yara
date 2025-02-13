rule Trojan_MSIL_r77RootKit_B_2147904879_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/r77RootKit.B!MTB"
        threat_id = "2147904879"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "r77RootKit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "SOFTWARE\\$77config\\pid" wide //weight: 2
        $x_2_2 = "SOFTWARE\\$77config\\paths" wide //weight: 2
        $x_2_3 = "/run /tn \\Microsoft\\Windows\\DiskCleanup\\SilentCleanup /I" wide //weight: 2
        $x_2_4 = "/create /tn \"{1}\" /tr \"'{0}'\" /sc onlogon /rl HIGHEST" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

