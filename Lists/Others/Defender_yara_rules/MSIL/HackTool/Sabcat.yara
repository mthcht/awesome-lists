rule HackTool_MSIL_Sabcat_A_2147726438_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MSIL/Sabcat.A!bit"
        threat_id = "2147726438"
        type = "HackTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Sabcat"
        severity = "High"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "program-update.net" wide //weight: 1
        $x_1_2 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_3 = "\\TPClassLibrary\\obj\\Release\\thost32.pdb" ascii //weight: 1
        $x_1_4 = {41 6e 74 69 76 69 72 4e 61 6d 65 4c 69 73 74 00}  //weight: 1, accuracy: High
        $x_1_5 = {41 64 64 49 6e 41 75 74 6f 53 74 61 72 74 00}  //weight: 1, accuracy: High
        $x_1_6 = {43 68 65 63 6b 41 6e 64 45 64 69 74 48 6f 73 74 73 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

