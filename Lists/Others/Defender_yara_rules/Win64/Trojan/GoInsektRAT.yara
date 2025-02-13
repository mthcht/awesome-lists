rule Trojan_Win64_GoInsektRAT_RP_2147915769_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/GoInsektRAT.RP!MTB"
        threat_id = "2147915769"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "GoInsektRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "pm3/connect/protls.SetPaswd" ascii //weight: 1
        $x_1_2 = "pm3/plugins/code.ShellCode" ascii //weight: 1
        $x_1_3 = "pm3/connect/prosni/client.go" ascii //weight: 1
        $x_1_4 = "pm3/connect/prosni/server.go" ascii //weight: 1
        $x_10_5 = "pm3/apps/Insekt/main.go" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

