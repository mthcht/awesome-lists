rule Ransom_MSIL_Maze_CCHD_2147901517_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Maze.CCHD!MTB"
        threat_id = "2147901517"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Maze"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "get_maze_" ascii //weight: 1
        $x_1_2 = "get_DECRYPT_FILES" ascii //weight: 1
        $x_1_3 = "What happened?" ascii //weight: 1
        $x_1_4 = "All your files, documents, photos, databases, and other important data are safely encrypted with reliable algorithms" ascii //weight: 1
        $x_1_5 = "How to get my files back?" ascii //weight: 1
        $x_1_6 = "The only method to restore your files is to purchase a unique for you private key which is securely stored on our servers" ascii //weight: 1
        $x_1_7 = "We understand your stress and worry" ascii //weight: 1
        $x_1_8 = "DECRYPT-FILES.txt" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

