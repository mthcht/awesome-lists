rule Ransom_MSIL_Lossymem_2147725275_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Lossymem"
        threat_id = "2147725275"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lossymem"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "LongTermMemoryLoss.exe" ascii //weight: 2
        $x_2_2 = "C:\\Users\\Asmcx15\\documents\\visual studio 2017\\Projects\\LongTermMemoryLoss\\LongTermMemoryLoss\\obj\\Debug\\LongTermMemoryLoss.pdb" ascii //weight: 2
        $x_2_3 = "LongTermMemoryLoss.WarnGUI.resources" ascii //weight: 2
        $x_2_4 = "LongTermMemoryLoss" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

