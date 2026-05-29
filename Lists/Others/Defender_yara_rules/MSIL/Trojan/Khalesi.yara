rule Trojan_MSIL_Khalesi_NA_2147906171_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Khalesi.NA!MTB"
        threat_id = "2147906171"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Khalesi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {61 60 13 00 ?? ?? 17 58 13 03 11 03 02}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Khalesi_ARA_2147970579_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Khalesi.ARA!MTB"
        threat_id = "2147970579"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Khalesi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "\\Stealerium\\Executor\\obj\\Release\\Executor.pdb" ascii //weight: 2
        $x_2_2 = "$cdaab557-f662-4aa6-bd13-1c7744e2a753" ascii //weight: 2
        $x_2_3 = "Disable defender and antivirus softwares" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

