rule Ransom_Linux_SorryRan_DA_2147968404_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/SorryRan.DA!MTB"
        threat_id = "2147968404"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "SorryRan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "github.com/qTox" ascii //weight: 1
        $x_1_2 = "TOX ID:" ascii //weight: 1
        $x_1_3 = "send an encrypted file" ascii //weight: 1
        $x_1_4 = "Sorry-ID" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

