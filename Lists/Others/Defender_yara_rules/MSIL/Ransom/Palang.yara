rule Ransom_MSIL_Palang_PAA_2147795976_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Palang.PAA!MTB"
        threat_id = "2147795976"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Palang"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "wbadmin delete systemstatebackup -deleteoldest" ascii //weight: 10
        $x_10_2 = "wbadmin delete backup -deleteoldest" ascii //weight: 10
        $x_1_3 = "files have been encrypted" ascii //weight: 1
        $x_1_4 = "Select ProcessorId From Win32_processor" ascii //weight: 1
        $x_1_5 = "SOFTWARE\\ECCT2" ascii //weight: 1
        $x_1_6 = "!README!" ascii //weight: 1
        $x_1_7 = "MrPalang@Cock.li" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

