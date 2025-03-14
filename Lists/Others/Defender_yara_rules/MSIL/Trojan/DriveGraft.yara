rule Trojan_MSIL_DriveGraft_A_2147936008_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DriveGraft.A!dha"
        threat_id = "2147936008"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DriveGraft"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "delMail" ascii //weight: 1
        $x_1_2 = "getCommandFromDraft" ascii //weight: 1
        $x_1_3 = "createEmailDraft" ascii //weight: 1
        $x_1_4 = "uploadxAsync" ascii //weight: 1
        $x_1_5 = "Tokeninit" ascii //weight: 1
        $x_1_6 = "OUTCommandControl" wide //weight: 1
        $x_1_7 = "/me/MailFolders/drafts/messages" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

