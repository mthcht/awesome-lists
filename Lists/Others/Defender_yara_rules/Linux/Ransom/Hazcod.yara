rule Ransom_Linux_Hazcod_A_2147890019_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/Hazcod.A!MTB"
        threat_id = "2147890019"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "Hazcod"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/hazcod/ransomwhere" ascii //weight: 1
        $x_1_2 = ".crypted" ascii //weight: 1
        $x_1_3 = "victimSize" ascii //weight: 1
        $x_1_4 = "dirtyLocked" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

