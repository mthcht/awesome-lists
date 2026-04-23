rule Trojan_Linux_CheckKics_DA_2147967574_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/CheckKics.DA!MTB"
        threat_id = "2147967574"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "CheckKics"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "-ldflags=\"-s -w -X github.com/Checkmarx/kics/v2/internal/constants.Version=v2.1.21 -X" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

