rule Backdoor_MSIL_IRCbot_E_2147653339_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/IRCbot.E"
        threat_id = "2147653339"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "IRCbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".dyndns.org" wide //weight: 1
        $x_1_2 = "!httpflood" wide //weight: 1
        $x_1_3 = "!synflood" wide //weight: 1
        $x_1_4 = "!udpflood" wide //weight: 1
        $x_1_5 = "!icmpflood" wide //weight: 1
        $x_1_6 = "PRIVMSG {0} :BotVersion: {1}" wide //weight: 1
        $x_1_7 = "PRIVMSG {0} :Windows Version: {1}" wide //weight: 1
        $x_1_8 = "PRIVMSG {0} :Username: {1}" wide //weight: 1
        $x_1_9 = "PRIVMSG {0} :Machinename: {1}" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule Backdoor_MSIL_IRCbot_F_2147653387_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/IRCbot.F"
        threat_id = "2147653387"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "IRCbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "!httpflooder" wide //weight: 10
        $x_1_2 = "irc.choopa.net" wide //weight: 1
        $x_1_3 = "\\svchost.exe\" start" wide //weight: 1
        $x_1_4 = "xx666KLMutex" wide //weight: 1
        $x_1_5 = "$RECYCLE.BIN\\svchost.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_MSIL_IRCbot_I_2147685667_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/IRCbot.I"
        threat_id = "2147685667"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "IRCbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Botkiller" ascii //weight: 1
        $x_1_2 = "!arme" wide //weight: 1
        $x_1_3 = "!http" wide //weight: 1
        $x_1_4 = "!tcp" wide //weight: 1
        $x_1_5 = "!slow" wide //weight: 1
        $x_1_6 = "!udp" wide //weight: 1
        $x_1_7 = "!ruskill" wide //weight: 1
        $x_1_8 = "!usb" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_IRCbot_I_2147685667_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/IRCbot.I"
        threat_id = "2147685667"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "IRCbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "!antivirus" wide //weight: 1
        $x_1_2 = "!botkill" wide //weight: 1
        $x_1_3 = "!flood.arme" wide //weight: 1
        $x_1_4 = "!flood.http" wide //weight: 1
        $x_1_5 = "!flood.tcp" wide //weight: 1
        $x_1_6 = "!flood.slowloris" wide //weight: 1
        $x_1_7 = "!flood.udp" wide //weight: 1
        $x_1_8 = "!ruskill" wide //weight: 1
        $x_1_9 = "!spread" wide //weight: 1
        $x_1_10 = "!download" wide //weight: 1
        $x_1_11 = "!visit" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (9 of ($x*))
}

rule Backdoor_MSIL_IRCbot_J_2147695998_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/IRCbot.J"
        threat_id = "2147695998"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "IRCbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\ircBot\\ircBot\\obj\\Release\\LolCache.pdb" ascii //weight: 1
        $x_1_2 = "Usage: !isup {url/ip} {stringtocheckfor/port}" wide //weight: 1
        $x_1_3 = "Sending {0} flood to {1} for {2} seconds with {3} threads" wide //weight: 1
        $x_1_4 = "bot.commander" wide //weight: 1
        $x_1_5 = "tcpsmash" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Backdoor_MSIL_IRCbot_K_2147709688_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/IRCbot.K!bit"
        threat_id = "2147709688"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "IRCbot"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\DelTenMat.VBS" wide //weight: 1
        $x_1_2 = {63 74 66 6d 6f 6e 2e 65 78 65 00 00 72 73 6d 61 69 6e 2e 65 78 65 00 00 33 36 30 54 72 61 79 2e 65 78 65 00 54 65 6e 49 6e 66 65 63 74}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_IRCbot_M_2147725373_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/IRCbot.M!bit"
        threat_id = "2147725373"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "IRCbot"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "43"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {00 49 72 63 42 6f 74 00}  //weight: 10, accuracy: High
        $x_10_2 = "PRIVMSG {0} :{1}" wide //weight: 10
        $x_10_3 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 10
        $x_10_4 = "SELECT * FROM AntivirusProduct" wide //weight: 10
        $x_1_5 = "CMDShell" wide //weight: 1
        $x_1_6 = "StartKeyLogger" wide //weight: 1
        $x_1_7 = "HideDir" wide //weight: 1
        $x_1_8 = "ScanLan" wide //weight: 1
        $x_1_9 = "InjectPersistence" wide //weight: 1
        $x_1_10 = "DownloadRun" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_MSIL_IRCbot_L_2147733602_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/IRCbot.L!bit"
        threat_id = "2147733602"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "IRCbot"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "USBInfection" ascii //weight: 1
        $x_1_2 = "SeafkoAgent.IRCClinet" ascii //weight: 1
        $x_1_3 = "StartKeyLogger" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

