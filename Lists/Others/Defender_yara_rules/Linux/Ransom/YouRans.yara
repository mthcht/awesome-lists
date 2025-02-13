rule Ransom_Linux_YouRans_A_2147849016_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/YouRans.A!MTB"
        threat_id = "2147849016"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "YouRans"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "main.encrypt" ascii //weight: 1
        $x_1_2 = "main.downloadReadme" ascii //weight: 1
        $x_1_3 = "YourRansom" ascii //weight: 1
        $x_1_4 = "saveKey" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

