rule Ransom_Linux_GentleCrypt_PA_2147969294_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/GentleCrypt.PA!MTB"
        threat_id = "2147969294"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "GentleCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "--marker--" ascii //weight: 1
        $x_1_2 = "reboot sleep " ascii //weight: 1
        $x_1_3 = "LOCKER_BACKGROUND" ascii //weight: 1
        $x_3_4 = "README-GENTLEMEN.txt" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

