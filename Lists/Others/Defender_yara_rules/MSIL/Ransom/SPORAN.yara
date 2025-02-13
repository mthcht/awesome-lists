rule Ransom_MSIL_SPORAN_DA_2147853297_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/SPORAN.DA!MTB"
        threat_id = "2147853297"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SPORAN"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Viagra\\dotnetfx35setup\\obj\\x86\\Debug\\dotnetfx35setup.pdb" ascii //weight: 1
        $x_1_2 = ".HTML in every folder, for instructions on how to get your files back." ascii //weight: 1
        $x_1_3 = "vssadmin.exe Delete Shadows /All /Quiet" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

