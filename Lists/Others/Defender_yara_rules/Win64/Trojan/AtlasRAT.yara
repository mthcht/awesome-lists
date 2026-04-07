rule Trojan_Win64_AtlasRAT_SX_2147966464_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AtlasRAT.SX!MTB"
        threat_id = "2147966464"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AtlasRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "40"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "Global\\{K8A9C1D9-FUCK-AE99-CLOSE-" ascii //weight: 20
        $x_10_2 = "$action = New-ScheduledTaskAction -Execute $obfuscatedPath;" ascii //weight: 10
        $x_5_3 = "/c ping -n 2 127.0.0.1 > nul && del" ascii //weight: 5
        $x_3_4 = "Wxfun.dll" ascii //weight: 3
        $x_2_5 = "Atlas" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

