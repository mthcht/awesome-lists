rule Ransom_MSIL_NiggaCrypt_PA_2147808583_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/NiggaCrypt.PA!MTB"
        threat_id = "2147808583"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NiggaCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "R_A_N_S_O_M_W_A_R_E___F_O_R___Y_O_U___N_I_G_G_A" ascii //weight: 1
        $x_1_2 = "\\READ_ME_FAGGOT.txt" wide //weight: 1
        $x_1_3 = "\\Heraxware.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

