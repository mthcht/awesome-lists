rule Trojan_Win64_TrojanProxy_MK_2147958294_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/TrojanProxy.MK!MTB"
        threat_id = "2147958294"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "TrojanProxy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_15_1 = {48 8d 04 11 83 e0 ?? 48 8d 52 01 48 03 c3 0f b6 44 05 d0 30 42 ff}  //weight: 15, accuracy: Low
        $x_10_2 = {48 8b c1 83 e0 ?? 48 03 c3 0f b6 44 05 d0 30 04 0a 48 ff c1}  //weight: 10, accuracy: Low
        $x_3_3 = "vmcheck.dll" ascii //weight: 3
        $x_2_4 = "VBoxHook.dll" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

