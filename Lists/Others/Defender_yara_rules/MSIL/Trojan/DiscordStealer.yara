rule Trojan_MSIL_DiscordStealer_XO_2147822915_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DiscordStealer.XO!MTB"
        threat_id = "2147822915"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DiscordStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "LimerBoy/StormKitty" ascii //weight: 1
        $x_1_2 = "RobloxStudioBrowser\\roblox.com" ascii //weight: 1
        $x_1_3 = "FromBase64String" ascii //weight: 1
        $x_1_4 = "Fuck.That.Bitch.Karen.I.Take.Her.To.Court" ascii //weight: 1
        $x_1_5 = "Invoke" ascii //weight: 1
        $x_1_6 = "DecryptDiscordToken" ascii //weight: 1
        $x_1_7 = "encrypted_key" ascii //weight: 1
        $x_1_8 = "\\passwords.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DiscordStealer_CXJK_2147849511_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DiscordStealer.CXJK!MTB"
        threat_id = "2147849511"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DiscordStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 35 00 2e 00 32 00 30 00 36 00 2e 00 32 00 32 00 37 00 2e 00 39 00 2f 00 44 00 49 00 53 00 43 00 4f 00 52 00 44 00 5f 00 57 00 4f 00 52 00 4d 00 2f}  //weight: 1, accuracy: High
        $x_1_2 = "content\": \"Sup bro, check this out !  Its a token gen !\", \"tts\" : false" wide //weight: 1
        $x_1_3 = "recipient_id" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DiscordStealer_CXFW_2147850215_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DiscordStealer.CXFW!MTB"
        threat_id = "2147850215"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DiscordStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {12 03 28 12 00 00 0a 0c 00 07 08 72 ?? ?? ?? ?? 28 ?? ?? ?? ?? 28 ?? ?? ?? ?? 0b 00 12 03 28 14 00 00 0a 13 04 11 04}  //weight: 1, accuracy: Low
        $x_1_2 = "Uk43uf0BLYg=" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DiscordStealer_PAB_2147899470_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DiscordStealer.PAB!MTB"
        threat_id = "2147899470"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DiscordStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "canary.discord.com/api/webhooks/1069222681557336064/" ascii //weight: 2
        $x_2_2 = "discord.com/api/webhooks/837762564246601738/" ascii //weight: 2
        $x_1_3 = "password-crypted.cockygrabber" ascii //weight: 1
        $x_1_4 = "GetAllPasswords" ascii //weight: 1
        $x_1_5 = "GetAllCookies" ascii //weight: 1
        $x_1_6 = "\\Temporary\\EdgePasswords.txt" ascii //weight: 1
        $x_1_7 = "\\Temporary\\EdgeCookies.txt" ascii //weight: 1
        $x_1_8 = "\\Temporary\\ChromePasswords.txt" ascii //weight: 1
        $x_1_9 = "\\Temporary\\ChromeCookies.txt" ascii //weight: 1
        $x_1_10 = "\\Temporary\\OperaPasswords.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 8 of ($x_1_*))) or
            ((2 of ($x_2_*) and 6 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_DiscordStealer_PAD_2147899471_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DiscordStealer.PAD!MTB"
        threat_id = "2147899471"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DiscordStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "taskkill /im System.dll" ascii //weight: 1
        $x_1_2 = "REG add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v DisableRegistryTools /t REG_DWORD /d 1 /f" ascii //weight: 1
        $x_1_3 = "REG add HKCU\\Software\\Policies\\Microsoft\\Windows\\System /v DisableCMD /t REG_DWORD /d 1 /f" ascii //weight: 1
        $x_1_4 = "ReVaLaTioN Keylogger Log" ascii //weight: 1
        $x_1_5 = "HKEY_CURRENT_USER\\Software\\IMVU\\username\\" ascii //weight: 1
        $x_1_6 = "HKEY_CURRENT_USER\\Software\\IMVU\\password\\" ascii //weight: 1
        $x_1_7 = "UploadFile" ascii //weight: 1
        $x_1_8 = "[LOG].txt" ascii //weight: 1
        $x_1_9 = "C:\\KFJD947DHC.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DiscordStealer_SZ_2147900613_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DiscordStealer.SZ!MTB"
        threat_id = "2147900613"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DiscordStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {00 09 28 04 00 00 06 17 8d 24 00 00 01 25 16 1f 22 9d 6f 24 00 00 0a 13 06 11 06 16 9a 0c 72 5d 02 00 70 11 06 28 25 00 00 0a 0d 03 2c 0c 08 6f 26 00 00 0a 1f 3b fe 01 2b 01 16 13 07 11 07 2c 03 00 2b 16 00 09 11 04 11 05 28 13 00 00 0a 6f 20 00 00 0a 13 08 11 08 2d a6}  //weight: 2, accuracy: High
        $x_2_2 = "ziggy.Properties.Resources" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DiscordStealer_GP_2147901079_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DiscordStealer.GP!MTB"
        threat_id = "2147901079"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DiscordStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {64 00 69 00 73 00 63 00 00 0b 6f 00 72 00 64 00 2e 00 63 00 00 11 6f 00 6d 00 2f 00 61 00 70 00 69 00 2f 00 77 00 00 0b 65 00 62 00 68 00 6f 00 6f 00 00 1f 6b 00 73 00 2f 00 38 00 31 00 30 00 39 00 39 00 34 00 33 00 35 00 34 00 36 00 33 00 33 00 00 31 35 00 37 00 32 00 34 00 33 00 32}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DiscordStealer_MK_2147960947_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DiscordStealer.MK!MTB"
        threat_id = "2147960947"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DiscordStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "35"
        strings_accuracy = "High"
    strings:
        $x_20_1 = {08 09 11 08 58 02 09 11 08 58 91 11 06 11 08 91 61 d2 9c 11 08 17 58 13 08 11 08 11 07 32 e1}  //weight: 20, accuracy: High
        $x_15_2 = "RIVATOR STEALER" ascii //weight: 15
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DiscordStealer_PAHH_2147961189_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DiscordStealer.PAHH!MTB"
        threat_id = "2147961189"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DiscordStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "SELECT ProcessorId FROM Win32_Processor" wide //weight: 2
        $x_1_2 = "\\Google\\Chrome\\User Data\\Default\\Local Storage\\leveldb" wide //weight: 1
        $x_2_3 = "GetVictimIP" ascii //weight: 2
        $x_1_4 = "\\Microsoft\\Edge\\User Data\\Default\\Local Storage\\leveldb" wide //weight: 1
        $x_1_5 = "KillDiscordProcesses" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

