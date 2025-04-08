rule Ransom_Win32_RansomWar_GVA_2147938153_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/RansomWar.GVA!MTB"
        threat_id = "2147938153"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "RansomWar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "War by [WarGame,#eof] ( **** ti amo anche se tu non mi ricambi )" ascii //weight: 1
        $x_1_2 = "Dear user," ascii //weight: 1
        $x_1_3 = "You are reading the mail!" ascii //weight: 1
        $x_1_4 = "Hi, you won " ascii //weight: 1
        $x_3_5 = "\\Software\\Microsoft\\Outlook Express\\5.0\\Mail" ascii //weight: 3
        $x_1_6 = "Warn on Mapi Send" ascii //weight: 1
        $x_1_7 = "MAPILogon" ascii //weight: 1
        $x_1_8 = "MAPIFindNext" ascii //weight: 1
        $x_1_9 = "MAPIReadMail" ascii //weight: 1
        $x_1_10 = "MAPISendMail" ascii //weight: 1
        $x_1_11 = "MAPILogoff" ascii //weight: 1
        $x_1_12 = "somesomeWar_EOF" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

