rule Ransom_Linux_Lynx_A_2147892805_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/Lynx.A!MTB"
        threat_id = "2147892805"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "Lynx"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RANSOMWARE_NOTE.README" ascii //weight: 1
        $x_1_2 = "LYNX_RANSOMWARE" ascii //weight: 1
        $x_1_3 = ".lynx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

