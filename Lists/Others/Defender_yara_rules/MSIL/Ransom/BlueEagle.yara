rule Ransom_MSIL_BlueEagle_MK_2147789392_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/BlueEagle.MK!MTB"
        threat_id = "2147789392"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "BlueEagle"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Blue_Eagle_Ransomware" ascii //weight: 1
        $x_1_2 = "RijndaelManaged" ascii //weight: 1
        $x_1_3 = "Rfc2898DeriveBytes" ascii //weight: 1
        $x_1_4 = "Ransomware.Resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

