rule Trojan_MSIL_Aenjaris_A_2147720095_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Aenjaris.A!bit"
        threat_id = "2147720095"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Aenjaris"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Virus Projeto\\Release\\Teste.pdb" ascii //weight: 1
        $x_1_2 = "\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\" ascii //weight: 1
        $x_1_3 = "serverjarvis.sytes.net/resource_vir/command.php?version=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Aenjaris_S_2147827337_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Aenjaris.S!MTB"
        threat_id = "2147827337"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Aenjaris"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://serverjarvis.sytes.net/resource_vir/command.php" ascii //weight: 1
        $x_1_2 = "jdfhdskjdgfyus543530665" ascii //weight: 1
        $x_1_3 = "Menu Iniciar\\Programas\\Inicializar" ascii //weight: 1
        $x_1_4 = "Fotos" ascii //weight: 1
        $x_1_5 = "Arquivos" ascii //weight: 1
        $x_1_6 = "Registros" ascii //weight: 1
        $x_1_7 = "Windows Update" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

