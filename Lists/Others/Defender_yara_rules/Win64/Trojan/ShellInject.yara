rule Trojan_Win64_ShellInject_DB_2147942061_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellInject.DB!MTB"
        threat_id = "2147942061"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "ShellcodeLoader" ascii //weight: 10
        $x_10_2 = "YwAYwAonvsgHUbnoYwAonvsgHUbnnvsgHUbn" ascii //weight: 10
        $x_1_3 = "smartscreen" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

