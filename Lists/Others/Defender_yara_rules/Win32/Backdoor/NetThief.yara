rule Backdoor_Win32_NetThief_2147493819_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/NetThief"
        threat_id = "2147493819"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "NetThief"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%s\\NetThief.exe" ascii //weight: 1
        $x_1_2 = "@netthief.net?subject=" ascii //weight: 1
        $x_1_3 = "CNetThiefDoc" ascii //weight: 1
        $x_1_4 = "\\Special.keyfile.security" ascii //weight: 1
        $x_1_5 = "%s\\RemoteComputer.part" ascii //weight: 1
        $x_1_6 = "consoleGetResult_Camera" ascii //weight: 1
        $x_1_7 = "consoleTakeOverDesktop" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Backdoor_Win32_NetThief_2147493819_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/NetThief"
        threat_id = "2147493819"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "NetThief"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "31"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "http://www.greenstuffsoft.net/nethief-callboard/Nethief_Version.dat" ascii //weight: 10
        $x_10_2 = "mailto:webmaster@greenstuffsoft.net?subject=" ascii //weight: 10
        $x_10_3 = "Nethief_Server.exe" ascii //weight: 10
        $x_1_4 = "FtpPassword" ascii //weight: 1
        $x_1_5 = "Nethief is testing...!" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_NetThief_2147493819_2
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/NetThief"
        threat_id = "2147493819"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "NetThief"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://www.netthief.net" ascii //weight: 1
        $x_1_2 = "mailto:greenstuff@netthief.net?subject=" ascii //weight: 1
        $x_1_3 = "\\RemoteComputer.part" ascii //weight: 1
        $x_1_4 = "\\Make.cfg" ascii //weight: 1
        $x_1_5 = "\\Maker.exe" ascii //weight: 1
        $x_1_6 = "\\NetThief.ini" ascii //weight: 1
        $x_1_7 = "ConsoleCore.dll" ascii //weight: 1
        $x_1_8 = "consoleConnectRemoteComputer" ascii //weight: 1
        $x_1_9 = "consoleGetResult_LoginCentralServer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

