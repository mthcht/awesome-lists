rule Trojan_MSIL_MSILLoader_RDA_2147846713_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/MSILLoader.RDA!MTB"
        threat_id = "2147846713"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "MSILLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ab403ea8-ab72-4507-b3cd-0f94a3ca1da1" ascii //weight: 1
        $x_1_2 = "Soft4Boost Disc Cover Studio" ascii //weight: 1
        $x_1_3 = "Sorentio Systems Ltd." ascii //weight: 1
        $x_1_4 = "//124.223.11.169:49673/Csyfrcotd.png" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

