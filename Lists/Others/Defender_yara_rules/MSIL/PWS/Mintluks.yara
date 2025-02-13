rule PWS_MSIL_Mintluks_A_2147707664_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/Mintluks.A"
        threat_id = "2147707664"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Mintluks"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "microsoft corporation" ascii //weight: 1
        $x_2_2 = "C:\\Users\\sa\\Downloads\\Untitled\\Untitled\\VB.NET" ascii //weight: 2
        $x_1_3 = "Internet_Explorer.pdb" ascii //weight: 1
        $x_5_4 = {02 91 20 3f ff ff ff 5f 1f 18 62 0a 06 7e ?? ?? ?? ?? 02 17 58 91 1f 10 62 60 0a}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_MSIL_Mintluks_B_2147726628_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/Mintluks.B"
        threat_id = "2147726628"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Mintluks"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "zCom.resources" ascii //weight: 1
        $x_1_2 = ".tmp.exe" wide //weight: 1
        $x_1_3 = "Deflate_D" ascii //weight: 1
        $x_1_4 = "DelMe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

