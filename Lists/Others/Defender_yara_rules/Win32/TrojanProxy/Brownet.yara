rule TrojanProxy_Win32_Brownet_A_2147646263_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Brownet.A"
        threat_id = "2147646263"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Brownet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_8_1 = "Brownie_BrownieService_" ascii //weight: 8
        $x_2_2 = "POPHack" ascii //weight: 2
        $x_2_3 = "GetBrownieComponents" ascii //weight: 2
        $x_2_4 = "GetSuperWebBrowser" ascii //weight: 2
        $x_1_5 = "CaptchaWorker" ascii //weight: 1
        $x_1_6 = "HotmailWorker" ascii //weight: 1
        $x_1_7 = "MailTaskWorker" ascii //weight: 1
        $x_1_8 = "GmailWorker" ascii //weight: 1
        $x_1_9 = "DeathByCaptcha" ascii //weight: 1
        $x_1_10 = "InternalBrowniewWorker" ascii //weight: 1
        $x_1_11 = "CraigslistTaskWorker" ascii //weight: 1
        $x_1_12 = "SetAddedTicketmasterTaskCompleted" ascii //weight: 1
        $x_1_13 = "SendBotStatusCompleted" ascii //weight: 1
        $x_1_14 = "BotKnockCompleted" ascii //weight: 1
        $x_1_15 = "CountDeadBots" ascii //weight: 1
        $x_1_16 = "CountExecuteBotsSpecified" ascii //weight: 1
        $x_1_17 = "CountOnlineBotsSpecified" ascii //weight: 1
        $x_1_18 = "CountDeadBotsSpecified" ascii //weight: 1
        $x_1_19 = "CountAllBotsSpecified" ascii //weight: 1
        $x_1_20 = "SendCraigslistCreateAccountRequest" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((14 of ($x_1_*))) or
            ((1 of ($x_2_*) and 12 of ($x_1_*))) or
            ((2 of ($x_2_*) and 10 of ($x_1_*))) or
            ((3 of ($x_2_*) and 8 of ($x_1_*))) or
            ((1 of ($x_8_*) and 6 of ($x_1_*))) or
            ((1 of ($x_8_*) and 1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_8_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_8_*) and 3 of ($x_2_*))) or
            (all of ($x*))
        )
}

