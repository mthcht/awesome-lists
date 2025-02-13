rule Trojan_Linux_Horsepill_A_2147835606_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Horsepill.A!MTB"
        threat_id = "2147835606"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Horsepill"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sh -c 'update-initramfs -k all -u 2" ascii //weight: 1
        $x_1_2 = "/reinfect-" ascii //weight: 1
        $x_1_3 = "mkstmp" ascii //weight: 1
        $x_1_4 = "splat_file" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

