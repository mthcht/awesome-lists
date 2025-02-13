rule Worm_MSIL_Tawsebot_A_2147632777_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:MSIL/Tawsebot.A"
        threat_id = "2147632777"
        type = "Worm"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tawsebot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[autorun]" wide //weight: 1
        $x_1_2 = "TargetInstance ISA 'Win32_USBControllerdevice'" wide //weight: 1
        $x_1_3 = "UAC desactivated" wide //weight: 1
        $x_1_4 = "Infected :" wide //weight: 1
        $x_1_5 = "!syn" wide //weight: 1
        $x_1_6 = "!udpflood" wide //weight: 1
        $x_1_7 = "!httpflood" wide //weight: 1
        $x_1_8 = "!seed" wide //weight: 1
        $x_1_9 = "!update" wide //weight: 1
        $x_1_10 = "!visilent" wide //weight: 1
        $x_1_11 = "!scanport" wide //weight: 1
        $x_1_12 = "!socks5" wide //weight: 1
        $x_1_13 = "!startddos" wide //weight: 1
        $x_1_14 = "!stopddos" wide //weight: 1
        $x_1_15 = "!dl (?<file>\\S+)" wide //weight: 1
        $x_1_16 = "dl http://(.*)/(.*?).(.*)" wide //weight: 1
        $x_1_17 = "Bot Killed !" wide //weight: 1
        $x_1_18 = "Bot Closed !" wide //weight: 1
        $x_1_19 = "Bot Updated !" wide //weight: 1
        $x_1_20 = "MSN Spreading started!" wide //weight: 1
        $x_1_21 = "p2p spread started" wide //weight: 1
        $x_1_22 = "downloaded and executed in" wide //weight: 1
        $x_1_23 = "USER {0} {1} * :{2}" wide //weight: 1
        $x_1_24 = "sniff_hit" wide //weight: 1
        $x_1_25 = {43 44 4b 65 79 7a 00}  //weight: 1, accuracy: High
        $x_1_26 = {4d 73 6e 73 70 72 65 61 64 00}  //weight: 1, accuracy: High
        $x_1_27 = {50 69 6e 67 53 65 6e 64 65 72 00}  //weight: 1, accuracy: High
        $x_1_28 = {75 64 70 66 6c 6f 6f 64 00}  //weight: 1, accuracy: High
        $x_1_29 = {48 74 74 70 46 6c 6f 6f 64 00}  //weight: 1, accuracy: High
        $x_1_30 = {53 75 70 65 72 53 79 6e 00}  //weight: 1, accuracy: High
        $x_1_31 = {55 53 42 53 70 72 65 61 64 00}  //weight: 1, accuracy: High
        $x_1_32 = {49 72 63 42 6f 74 00}  //weight: 1, accuracy: High
        $x_1_33 = {41 6e 74 69 44 65 62 75 67 00}  //weight: 1, accuracy: High
        $x_1_34 = {41 6e 74 69 56 69 72 74 75 61 6c 50 43 00}  //weight: 1, accuracy: High
        $x_1_35 = {4b 33 79 50 77 6e 5a 30 72 65 64 00}  //weight: 1, accuracy: High
        $x_1_36 = {45 6e 61 62 6c 65 44 69 73 54 61 73 6b 4d 00}  //weight: 1, accuracy: High
        $x_1_37 = {45 6e 61 62 6c 65 44 69 73 52 65 67 65 64 69 74 00}  //weight: 1, accuracy: High
        $x_1_38 = {45 6e 61 62 6c 65 44 69 73 43 4d 44 00}  //weight: 1, accuracy: High
        $x_1_39 = {45 6e 61 62 6c 47 61 6d 65 53 74 65 61 6c 65 72 00}  //weight: 1, accuracy: High
        $x_1_40 = {45 6e 61 62 6c 65 55 53 42 53 70 72 65 61 64 00}  //weight: 1, accuracy: High
        $x_1_41 = {74 78 74 49 6e 66 65 63 74 65 64 50 63 69 6e 66 6f 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule Worm_MSIL_Tawsebot_B_2147637305_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:MSIL/Tawsebot.B"
        threat_id = "2147637305"
        type = "Worm"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tawsebot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "342"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "WoRmY" ascii //weight: 100
        $x_100_2 = "infectDrives" ascii //weight: 100
        $x_100_3 = "botUser" ascii //weight: 100
        $x_100_4 = "botPass" ascii //weight: 100
        $x_100_5 = "onpayroll.net" wide //weight: 100
        $x_10_6 = "[autorun]" wide //weight: 10
        $x_10_7 = "Infected !" wide //weight: 10
        $x_10_8 = "P2P Folders!" wide //weight: 10
        $x_10_9 = "wireshark network analyzer" wide //weight: 10
        $x_10_10 = "NICK" wide //weight: 10
        $x_10_11 = "JOIN" wide //weight: 10
        $x_10_12 = "QUIT" wide //weight: 10
        $x_1_13 = "\\My Shared Folder" wide //weight: 1
        $x_1_14 = "\\Shared" wide //weight: 1
        $x_1_15 = "\\Downloads" wide //weight: 1
        $x_1_16 = "\\incoming" wide //weight: 1
        $x_1_17 = "\\shared folder" wide //weight: 1
        $x_1_18 = "\\grokster\\my grokster" wide //weight: 1
        $x_1_19 = "\\tesla\\files" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_100_*) and 4 of ($x_10_*) and 2 of ($x_1_*))) or
            ((3 of ($x_100_*) and 5 of ($x_10_*))) or
            ((4 of ($x_100_*))) or
            (all of ($x*))
        )
}

rule Worm_MSIL_Tawsebot_C_2147646969_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:MSIL/Tawsebot.C"
        threat_id = "2147646969"
        type = "Worm"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tawsebot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "AntiSandboxie" ascii //weight: 4
        $x_3_2 = "FakeErrorMessage" ascii //weight: 3
        $x_2_3 = "goto Repeat" wide //weight: 2
        $x_2_4 = "StealerLog" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

