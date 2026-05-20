rule Trojan_Win64_Phemedrone_APD_2147969833_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Phemedrone.APD!MTB"
        threat_id = "2147969833"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Phemedrone"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {48 8b c3 4d 8d 76 ?? 83 e0 ?? 48 ff c3 0f b6 44 05 ?? 41 30 46 ?? 48 83 e9 01 75}  //weight: 5, accuracy: Low
        $x_5_2 = {34 5a 0f b6 c0 66 89 44 4d ?? 48 ff c1 48 83 f9 0c 7c}  //weight: 5, accuracy: Low
        $x_1_3 = "IsProcessorFeaturePresent" ascii //weight: 1
        $x_1_4 = "clr: payload_zeroed" ascii //weight: 1
        $x_1_5 = "decrypt_ok bytes=%u" ascii //weight: 1
        $x_1_6 = "apis_resolved" ascii //weight: 1
        $x_1_7 = "ntdll_unhooked" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

