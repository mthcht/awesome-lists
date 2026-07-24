rule Trojan_Win64_Yephiler_AHB_2147974467_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Yephiler.AHB!MTB"
        threat_id = "2147974467"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Yephiler"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "60"
        strings_accuracy = "High"
    strings:
        $x_30_1 = "zerin_file_encrypt_v1" ascii //weight: 30
        $x_20_2 = "Global\\ZerinAgentLock" ascii //weight: 20
        $x_10_3 = "Global\\ZerinElevOK" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

