rule Trojan_Win64_LuxLoader_AAA_2147968034_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LuxLoader.AAA!AMTB"
        threat_id = "2147968034"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LuxLoader"
        severity = "Critical"
        info = "AMTB: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_15_1 = "\\LuxLoader\\obj\\Release\\net8.0-windows\\win-x64\\LuxLoader.pdb" ascii //weight: 15
        $x_1_2 = "LuxLoader.dll" wide //weight: 1
        $x_1_3 = "LuxLoader.Components.Browsers" ascii //weight: 1
        $x_1_4 = "LuxLoader.Components.Messenger.Discord" ascii //weight: 1
        $x_1_5 = "https://github.com/LuxLoader" wide //weight: 1
        $x_1_6 = "<KillAllBrowsers>d__1" ascii //weight: 1
        $x_1_7 = "StealSessions" ascii //weight: 1
        $x_1_8 = "passwords.txt" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

