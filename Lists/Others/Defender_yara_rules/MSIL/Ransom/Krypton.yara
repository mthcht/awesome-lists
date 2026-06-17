rule Ransom_MSIL_Krypton_AMTB_2147971769_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Krypton!AMTB"
        threat_id = "2147971769"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Krypton"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "KryptonRansomware.Utils" ascii //weight: 1
        $x_1_2 = "\\kryptonransomware\\src\\obj\\Release\\net10.0-windows\\win-x64\\svchost.pdb" ascii //weight: 1
        $x_1_3 = "YOUR_KEY_krypton.bin" ascii //weight: 1
        $x_1_4 = ".krypton" ascii //weight: 1
        $x_1_5 = "README_KRYPTON.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

