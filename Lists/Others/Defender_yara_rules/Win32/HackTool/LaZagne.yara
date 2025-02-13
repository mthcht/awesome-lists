rule HackTool_Win32_LaZagne_2147725068_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/LaZagne"
        threat_id = "2147725068"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "LaZagne"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $n_20_1 = "Microsoft.Cyber.ObservationDetectors.dll" ascii //weight: -20
        $n_20_2 = "OneCyberFT@microsoft.com" ascii //weight: -20
        $x_6_3 = "laZagne.exe.manifest" ascii //weight: 6
        $x_3_4 = "lazagne.config" ascii //weight: 3
        $x_3_5 = "lazagne.softwares" ascii //weight: 3
        $x_3_6 = "mimikatz" ascii //weight: 3
        $x_2_7 = "lazagne" ascii //weight: 2
        $x_3_8 = " name=\"laZagne1\" " ascii //weight: 3
        $x_2_9 = ".lsa_secrets" ascii //weight: 2
        $x_2_10 = ".windows.secretsdump" ascii //weight: 2
        $x_2_11 = ".wifi.wifipass" ascii //weight: 2
        $x_1_12 = ".browsers.ie" ascii //weight: 1
        $x_1_13 = ".chats.jitsi" ascii //weight: 1
        $x_1_14 = ".games.kalypsomedia" ascii //weight: 1
        $x_1_15 = ".git.gitforwindows" ascii //weight: 1
        $x_1_16 = ".sysadmin.apachedirectorystudio" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((3 of ($x_2_*) and 5 of ($x_1_*))) or
            ((4 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_3_*) and 3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 4 of ($x_2_*))) or
            ((2 of ($x_3_*) and 5 of ($x_1_*))) or
            ((2 of ($x_3_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_3_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_3_*) and 3 of ($x_2_*))) or
            ((3 of ($x_3_*) and 2 of ($x_1_*))) or
            ((3 of ($x_3_*) and 1 of ($x_2_*))) or
            ((4 of ($x_3_*))) or
            ((1 of ($x_6_*) and 5 of ($x_1_*))) or
            ((1 of ($x_6_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_6_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_6_*) and 3 of ($x_2_*))) or
            ((1 of ($x_6_*) and 1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_6_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_6_*) and 2 of ($x_3_*))) or
            (all of ($x*))
        )
}

