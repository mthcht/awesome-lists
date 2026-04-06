rule Backdoor_Win64_Brushworm_C_2147966397_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/Brushworm.C!MTB"
        threat_id = "2147966397"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "Brushworm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {33 c9 ff 15 ?? ?? ?? ?? 89 44 24 ?? b9 01 00 00 00 ff 15 ?? ?? ?? ?? 89 44 24 ?? 81 7c 24 ?? 00 04 00 00 7f ?? 81 7c 24 ?? 00 03 00 00 7f}  //weight: 5, accuracy: Low
        $x_5_2 = {48 8b 44 24 ?? 48 ff c0 48 89 44 24 ?? 48 8b 84 24 ?? ?? ?? ?? 48 39 44 24 ?? 73 48 48 6b 44 24 ?? 20 48 8b 8c 24 ?? ?? ?? ?? 48 03 c8 48 8b c1 48 8b c8 e8 ?? ?? ?? ?? c7 44 24 ?? 01 00 00 00 41 b9 ff ff ff ff 4c 8b c0 ba ff ff ff ff 48 8d 4c 24 ?? ff 15}  //weight: 5, accuracy: Low
        $x_1_3 = "sandbox" wide //weight: 1
        $x_1_4 = "VIRTUALBOX" ascii //weight: 1
        $x_1_5 = "VMWARE" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

