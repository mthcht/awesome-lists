rule TrojanDownloader_MSIL_Fleadew_A_2147722500_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Fleadew.A!bit"
        threat_id = "2147722500"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Fleadew"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 66 00 2e 00 6c 00 65 00 77 00 64 00 2e 00 73 00 65 00 2f 00 [0-64] 2e 00 6a 00 70 00 67 00}  //weight: 10, accuracy: Low
        $x_1_2 = "schtasks /create /sc minute /mo 1 /tn SidebarUpdate /tr" wide //weight: 1
        $x_1_3 = ":Zone.Identifier" wide //weight: 1
        $x_1_4 = "SandboxieDcomLaunch" wide //weight: 1
        $x_1_5 = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

