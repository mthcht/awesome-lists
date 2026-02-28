rule Ransom_Linux_SinobiCrypt_PA_2147963908_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/SinobiCrypt.PA!MTB"
        threat_id = "2147963908"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "SinobiCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "R29vZCBhZnRlcm5vb24sIHdlIGFyZSBTaW5vYmkgR3JvdXAuDQ" ascii //weight: 4
        $x_1_2 = "/README.txt" ascii //weight: 1
        $x_1_3 = "Force stop all ESXi VMs" ascii //weight: 1
        $x_1_4 = "Encrypt only specified file(s)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

