rule TrojanSpy_AndroidOS_Origami_A_2147781996_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Origami.A!MTB"
        threat_id = "2147781996"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Origami"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "T3V0R29pbmcg" ascii //weight: 1
        $x_1_2 = "SW5jb21pbmcg" ascii //weight: 1
        $x_1_3 = "a2V5cy50eHQ= " ascii //weight: 1
        $x_1_4 = "b3JnLnRob3VnaHRjcmltZS5zZWN1cmVzbXMvLmNvbnZlcnNhdGlvbi5Db252ZXJzYXRpb25BY3Rpdml0eQ==" ascii //weight: 1
        $x_1_5 = "Y29tLndoYXRzYXBwLy5Db252ZXJzYXRpb24=" ascii //weight: 1
        $x_1_6 = "Q2FsbExvZ3MudHh0" ascii //weight: 1
        $x_1_7 = "c21zLnR4dA==" ascii //weight: 1
        $x_1_8 = "Q2VsbElk" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule TrojanSpy_AndroidOS_Origami_2147798297_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Origami.z"
        threat_id = "2147798297"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Origami"
        severity = "Critical"
        info = "z: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".amr::Added" ascii //weight: 1
        $x_1_2 = "Checking For Update" ascii //weight: 1
        $x_1_3 = "123456789032145" ascii //weight: 1
        $x_1_4 = "L0FuZHJvaWQvLnN5c3RlbS8=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_Origami_B_2147809329_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Origami.B!MTB"
        threat_id = "2147809329"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Origami"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "1yeEJ9Ea7dalhZIe5DVniw==" ascii //weight: 1
        $x_1_2 = "fIOeTNMvibZ29Otolc35sQ==" ascii //weight: 1
        $x_1_3 = "CctTransportBackend" ascii //weight: 1
        $x_1_4 = "Lcom/gentwo/info/ioio/wrng" ascii //weight: 1
        $x_1_5 = "Le/b/a/f/b/a" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

