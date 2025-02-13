rule Trojan_MSIL_Xlceint_A_2147728358_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Xlceint.A!bit"
        threat_id = "2147728358"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Xlceint"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 78 43 6c 69 65 6e 74 2e 43 6f 72 65}  //weight: 1, accuracy: High
        $x_1_2 = "xClient.Properties.Resources" wide //weight: 1
        $x_1_3 = "https://freegeoip.net/xml/" wide //weight: 1
        $x_1_4 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_5 = "TryUacTrick" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_MSIL_Xlceint_A_2147786660_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Xlceint.A!MTB"
        threat_id = "2147786660"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Xlceint"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "xClient.Core.Elevation" ascii //weight: 3
        $x_3_2 = "SELECT Caption FROM Win32_OperatingSystem" ascii //weight: 3
        $x_3_3 = "SELECT * FROM AntivirusProduct" ascii //weight: 3
        $x_3_4 = "Select * From Win32_ComputerSystem" ascii //weight: 3
        $x_3_5 = "SELECT * FROM FirewallProduct" ascii //weight: 3
        $x_3_6 = "del /A:H" ascii //weight: 3
        $x_3_7 = "5RB3hfPSDRwaSMR3bm4i" ascii //weight: 3
        $x_3_8 = "DoMouseEvent" ascii //weight: 3
        $x_3_9 = "HotKeyHandler" ascii //weight: 3
        $x_3_10 = "add_OnHotKeysDownOnce" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

