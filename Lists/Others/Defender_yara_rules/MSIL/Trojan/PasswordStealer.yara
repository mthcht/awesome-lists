rule Trojan_MSIL_PasswordStealer_PA_2147752176_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PasswordStealer.PA!MTB"
        threat_id = "2147752176"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PasswordStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "grab_photo_from_desktop" ascii //weight: 1
        $x_1_2 = "grab_docs_from_Document" ascii //weight: 1
        $x_1_3 = "upload_screenshot" ascii //weight: 1
        $x_1_4 = "browser_passwords" ascii //weight: 1
        $x_1_5 = "emails_pass" ascii //weight: 1
        $x_1_6 = "upload_passwords" ascii //weight: 1
        $x_1_7 = "SELECT * FROM AntivirusProduct" wide //weight: 1
        $x_1_8 = "IMAP Password" wide //weight: 1
        $x_1_9 = "POP3 Password" wide //weight: 1
        $x_1_10 = "credit_cards" wide //weight: 1
        $x_1_11 = "Card Number" wide //weight: 1
        $x_1_12 = "Graber From" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PasswordStealer_AAA_2147972887_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PasswordStealer.AAA!AMTB"
        threat_id = "2147972887"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PasswordStealer"
        severity = "Critical"
        info = "AMTB: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "\\kolos\\Desktop\\Projects\\Pidolib\\pidlob\\Source\\plugin\\Desktop\\obj\\Release\\Desktop.pdb" ascii //weight: 10
        $x_10_2 = "\\libkasource\\plugin\\Desktop\\obj\\Release\\Desktop.pdb" ascii //weight: 10
        $x_1_3 = "MOUSEEVENTF_WHEEL" ascii //weight: 1
        $x_1_4 = "get_RemoteEndPoint" ascii //weight: 1
        $x_1_5 = "CSystem.Reflection.SharpDXTypeExtensions+<GetCustomAttributes>" ascii //weight: 1
        $x_1_6 = "Capture" wide //weight: 1
        $x_1_7 = "Desktop.dll" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 5 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_PasswordStealer_AAB_2147972888_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PasswordStealer.AAB!AMTB"
        threat_id = "2147972888"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PasswordStealer"
        severity = "Critical"
        info = "AMTB: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "\\Emrepkeer\\source\\repos\\GetDiscordToken\\GetDiscordToken\\obj\\Release\\net10.0-windows\\win-x64\\Software.pdb" ascii //weight: 10
        $x_2_2 = "SELECT host_key, name, encrypted_value FROM cookies WHERE host_key LIKE '%discord%' OR host_key LIKE '%roblox%' LIMIT 20" wide //weight: 2
        $x_2_3 = "<Form1_Load>" ascii //weight: 2
        $x_2_4 = "Kill" ascii //weight: 2
        $x_2_5 = "GetMasterKey" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

