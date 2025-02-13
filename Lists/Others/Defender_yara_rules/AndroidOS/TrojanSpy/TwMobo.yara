rule TrojanSpy_AndroidOS_TwMobo_A_2147782147_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/TwMobo.A!MTB"
        threat_id = "2147782147"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "TwMobo"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "AutoBot::Socket::Controle" ascii //weight: 2
        $x_1_2 = "com/gservice/receiver/AdmR;" ascii //weight: 1
        $x_1_3 = "autobot/Acessibilidade" ascii //weight: 1
        $x_1_4 = "Acessibilidade_Click" ascii //weight: 1
        $x_1_5 = "Acessibilidade_SocketControle" ascii //weight: 1
        $x_1_6 = "controle_remoto" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_AndroidOS_TwMobo_B_2147788114_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/TwMobo.B!MTB"
        threat_id = "2147788114"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "TwMobo"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Lcom/gservice/activity/Adm" ascii //weight: 1
        $x_1_2 = "controle_remoto" ascii //weight: 1
        $x_1_3 = "Acessibilidade_Click" ascii //weight: 1
        $x_1_4 = "/autobot/Acessibilidade" ascii //weight: 1
        $x_1_5 = "solutionsdevneway.net" ascii //weight: 1
        $x_1_6 = {2f 67 61 74 65 77 61 79 2f [0-16] 2e 70 68 70}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule TrojanSpy_AndroidOS_TwMobo_BA_2147812363_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/TwMobo.BA!MTB"
        threat_id = "2147812363"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "TwMobo"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Lcom/gservice/autobot/Acessibilidade" ascii //weight: 1
        $x_1_2 = "atualservicenovo.hopto.org" ascii //weight: 1
        $x_1_3 = {2f 74 65 6c 61 73 [0-16] 2e 70 68 70 3f 68 77 69 64 3d}  //weight: 1, accuracy: Low
        $x_1_4 = "controle_remoto" ascii //weight: 1
        $x_1_5 = "Acessibilidade_Click" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

