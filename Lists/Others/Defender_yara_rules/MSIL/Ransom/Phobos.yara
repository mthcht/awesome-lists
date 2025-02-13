rule Ransom_MSIL_Phobos_PA_2147793989_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Phobos.PA!MTB"
        threat_id = "2147793989"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Phobos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "!README!.hta" wide //weight: 1
        $x_1_2 = "Shadowofdeath" wide //weight: 1
        $x_1_3 = "All your files have been encrypted!" wide //weight: 1
        $x_1_4 = "wbadmin delete systemstatebackup -deleteoldest" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Phobos_BK_2147931601_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Phobos.BK!MTB"
        threat_id = "2147931601"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Phobos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {02 08 1b 58 1a 59 02 8e 69 5d 91 59 20 ff 00 00 00 58 17 58 20 00 01 00 00 5d d2 9c 08 17 58 0c 08 6a 02 8e 69 17 59 6a 06 17 58 6e 5a 31}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

