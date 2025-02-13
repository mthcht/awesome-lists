rule Trojan_Win64_Relatsnif_E_2147919386_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Relatsnif.E"
        threat_id = "2147919386"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Relatsnif"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Failed to rename {} to {}. Error code: {}" ascii //weight: 1
        $x_1_2 = "Renamed {} to {}." ascii //weight: 1
        $x_1_3 = "File {} {}." ascii //weight: 1
        $x_1_4 = "{} {}. Error code: {}" ascii //weight: 1
        $x_1_5 = "Overwrote {} with {} {} {})" ascii //weight: 1
        $x_1_6 = "[{}] [{}] {}" ascii //weight: 1
        $x_1_7 = "{} {} after renaming it." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

