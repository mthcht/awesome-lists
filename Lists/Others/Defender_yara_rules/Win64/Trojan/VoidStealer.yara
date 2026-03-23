rule Trojan_Win64_VoidStealer_APSB_2147965347_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/VoidStealer.APSB!MTB"
        threat_id = "2147965347"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "VoidStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {8b 44 24 20 8b 4c 24 20 8b 15 ?? ?? ?? ?? ff c1 8b 05 ?? ?? ?? ?? d3 e2 33 c2 89 05 ?? ?? ?? ?? 8b 44 24 20 ff c0 89 44 24 20 8b 44 24 20 83 f8 03 7c}  //weight: 4, accuracy: Low
        $x_1_2 = "VMware Tools" ascii //weight: 1
        $x_1_3 = "VirtualBox Guest Additions" ascii //weight: 1
        $x_1_4 = "\\CurrentControlSet\\Services\\vmhgfs" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

