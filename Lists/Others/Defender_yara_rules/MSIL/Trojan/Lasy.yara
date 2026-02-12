rule Trojan_MSIL_Lasy_PGLA_2147962893_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lasy.PGLA!MTB"
        threat_id = "2147962893"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lasy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "pa93u1H8aw4UaOR18S7sRYbm78BIelmIgPt6bQ0aPkaWlXfqHd5xLStinXHNG8w+suv+8WlNZvuZ4mASNzggVKyMVJoF8mUDImP5UMs3lja" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

