rule TrojanDownloader_MSIL_Bsymem_ABS_2147841503_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Bsymem.ABS!MTB"
        threat_id = "2147841503"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bsymem"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "ciadecompras.com/stubs/Encoding.txt" wide //weight: 2
        $x_2_2 = "V1K1NG\\OneDrive\\Desktop\\BOTNET TOOLS\\WindowsFormsApp1\\WindowsFormsApp1\\obj\\Debug\\WindowsFormsApp1.pdb" ascii //weight: 2
        $x_1_3 = "WindowsFormsApp1.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Bsymem_ABY_2147842022_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Bsymem.ABY!MTB"
        threat_id = "2147842022"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bsymem"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {73 15 00 00 0a 0a 16 0b 2b 19 06 03 07 18 6f ?? ?? ?? 0a 1f 10 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 07 18 58 0b 07 03}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

