rule Ransom_Linux_Echoraix_SB_2147808333_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/Echoraix.SB!xp"
        threat_id = "2147808333"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "Echoraix"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "main.EncFile" ascii //weight: 1
        $x_1_2 = "main.randSeq" ascii //weight: 1
        $x_1_3 = "main.chDir" ascii //weight: 1
        $x_1_4 = "main.writemessage" ascii //weight: 1
        $x_1_5 = "main.makesecret" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

