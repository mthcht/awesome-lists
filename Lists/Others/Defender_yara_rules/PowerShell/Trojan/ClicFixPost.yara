rule Trojan_PowerShell_ClicFixPost_Z_2147972908_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:PowerShell/ClicFixPost.Z!MTB"
        threat_id = "2147972908"
        type = "Trojan"
        platform = "PowerShell: "
        family = "ClicFixPost"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "whoami.exe\" /groups" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

