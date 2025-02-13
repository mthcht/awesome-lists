rule TrojanDownloader_AndroidOS_Bahamut_J_2147920166_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:AndroidOS/Bahamut.J!MTB"
        threat_id = "2147920166"
        type = "TrojanDownloader"
        platform = "AndroidOS: Android operating system"
        family = "Bahamut"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "orga.user.securesoft.MessageHandler" ascii //weight: 5
        $x_5_2 = "Lorga/security/certargs/ShellService" ascii //weight: 5
        $x_1_3 = "update.jar" ascii //weight: 1
        $x_1_4 = "oha.alpinemap.net" ascii //weight: 1
        $x_1_5 = "doSendMessageToClient_UIT" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 2 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

