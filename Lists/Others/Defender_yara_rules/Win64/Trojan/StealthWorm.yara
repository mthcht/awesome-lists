rule Trojan_Win64_StealthWorm_DA_2147924485_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/StealthWorm.DA!MTB"
        threat_id = "2147924485"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "StealthWorm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Wiping system..." ascii //weight: 10
        $x_1_2 = "C:\\Windows\\Memory.dmp" ascii //weight: 1
        $x_10_3 = "Deleted file:" ascii //weight: 10
        $x_1_4 = "C:\\hiberfil.sys" ascii //weight: 1
        $x_1_5 = "No threats detected." ascii //weight: 1
        $x_1_6 = "Failed to delete directory:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

