rule Trojan_MSIL_BlackLineStealer_AA_2147968039_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/BlackLineStealer.AA!AMTB"
        threat_id = "2147968039"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "BlackLineStealer"
        severity = "Critical"
        info = "AMTB: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<TakeScreenshot>d__20" ascii //weight: 1
        $x_1_2 = "<KeyLoggerLoop>d__40" ascii //weight: 1
        $x_1_3 = "<StealDiscordTokens>d__22" ascii //weight: 1
        $x_1_4 = "VictimRAT.Properties.Resources" wide //weight: 1
        $x_1_5 = "!steal_all" wide //weight: 1
        $x_1_6 = "All steal commands executed." wide //weight: 1
        $x_1_7 = "**You have been hacked by Anonymous!**" wide //weight: 1
        $x_1_8 = "powershell Set-MpPreference -DisableRealtimeMonitoring $true" wide //weight: 1
        $x_1_9 = "VictimRAT\\VictimRAT\\obj\\Release\\VictimRAT.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

