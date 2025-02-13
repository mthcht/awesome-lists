rule Ransom_Linux_RevilCrypt_PA_2147786329_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/RevilCrypt.PA!MTB"
        threat_id = "2147786329"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "RevilCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Revix 1.1c" ascii //weight: 1
        $x_1_2 = "elf.exe --path /vmfs/ --threads 5" ascii //weight: 1
        $x_1_3 = "system(\"esxcli vm process kill --type=force --world-id=\" $1)" ascii //weight: 1
        $x_1_4 = "iji iji iji iji ij| ENCRYPTED |ji iji ifi iji iji iji" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

