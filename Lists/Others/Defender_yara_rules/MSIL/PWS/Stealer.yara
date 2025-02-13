rule PWS_MSIL_Stealer_DHA_2147755907_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/Stealer.DHA!MTB"
        threat_id = "2147755907"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "AnarchyGrabber" wide //weight: 1
        $x_1_2 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 6d 00 65 00 64 00 69 00 61 00 2e 00 64 00 69 00 73 00 63 00 6f 00 72 00 64 00 61 00 70 00 70 00 2e 00 6e 00 65 00 74 00 2f 00 61 00 74 00 74 00 61 00 63 00 68 00 6d 00 65 00 6e 00 74 00 73 00 2f 00 [0-32] 2f 00 [0-32] 2f 00 41 00 6e 00 61 00 72 00 63 00 68 00 79 00 2e 00 70 00 6e 00 67 00}  //weight: 1, accuracy: Low
        $x_1_3 = "\\Local Storage\\leveldb" wide //weight: 1
        $x_1_4 = "Roaming\\Discord" wide //weight: 1
        $x_1_5 = "Roaming\\discordptb" wide //weight: 1
        $x_1_6 = "username" wide //weight: 1
        $x_1_7 = "AvatarUrl" wide //weight: 1
        $x_1_8 = "Anarchy Token Grabber" wide //weight: 1
        $x_1_9 = "\\discord\\Local Storage\\leveldb\\" wide //weight: 1
        $x_1_10 = "Webhook" wide //weight: 1
        $x_1_11 = "http://ipv4bot.whatismyipaddress.com/" wide //weight: 1
        $x_1_12 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 77 00 77 00 77 00 2e 00 6c 00 6f 00 67 00 6f 00 6c 00 79 00 6e 00 78 00 2e 00 63 00 6f 00 6d 00 2f 00 69 00 6d 00 61 00 67 00 65 00 73 00 2f 00 6c 00 6f 00 67 00 6f 00 6c 00 79 00 6e 00 78 00 2f 00 31 00 62 00 2f 00 [0-32] 2e 00 70 00 6e 00 67 00}  //weight: 1, accuracy: Low
        $x_1_13 = "Discord Token Stealer" wide //weight: 1
        $x_1_14 = "MzYxNTg1MjAzMTcwMzc3NzI4.XOxP9g.hoc5kfJFRcRvR77Zpp7kRxUY3nk" wide //weight: 1
        $x_1_15 = "VXYN Bot" wide //weight: 1
        $x_1_16 = "avatar_url" wide //weight: 1
        $x_1_17 = "RadicalRaidBot" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule PWS_MSIL_Stealer_DHC_2147755908_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/Stealer.DHC!MTB"
        threat_id = "2147755908"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Discord.exe" wide //weight: 1
        $x_1_2 = "\\Local\\Discord" wide //weight: 1
        $x_1_3 = "ObbedCode Token Bot" wide //weight: 1
        $x_1_4 = "ProjectUpdatedDiscordStealer" wide //weight: 1
        $x_1_5 = "TOKENS!" wide //weight: 1
        $x_1_6 = "/C ping 1.1.1.1 -n 1 -w 3000 > Nul & Del" wide //weight: 1
        $x_1_7 = "https://static.nulled.to/uploads/profile/" wide //weight: 1
        $x_1_8 = "Webhook" ascii //weight: 1
        $x_1_9 = "password" ascii //weight: 1
        $x_1_10 = "\\discord\\Local Storage\\leveldb\\" wide //weight: 1
        $x_1_11 = "Discord" wide //weight: 1
        $x_1_12 = "https://danbooru.donmai.us/data/" wide //weight: 1
        $x_1_13 = "avatar_url" wide //weight: 1
        $x_1_14 = "Token :" wide //weight: 1
        $x_1_15 = "content" wide //weight: 1
        $x_1_16 = "https://wtfismyip.com/text" wide //weight: 1
        $x_1_17 = "https://discordapp.com/api/webhooks/" wide //weight: 1
        $x_1_18 = "No_Virus_EXE_By_Haf" ascii //weight: 1
        $x_1_19 = "No valid .ldb or .log file found" wide //weight: 1
        $x_1_20 = "Haf.exe" wide //weight: 1
        $x_1_21 = "\\AppData\\" wide //weight: 1
        $x_1_22 = "\\Local Storage\\leveldb" wide //weight: 1
        $x_1_23 = "*.ldb" wide //weight: 1
        $x_1_24 = "*.log" wide //weight: 1
        $x_1_25 = "Roaming\\Discord" wide //weight: 1
        $x_1_26 = "Roaming\\discordcanary" wide //weight: 1
        $x_1_27 = "Roaming\\discordptb" wide //weight: 1
        $x_1_28 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_29 = "//moanfor.me/mc.zip" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (9 of ($x*))
}

rule PWS_MSIL_Stealer_DHD_2147755909_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/Stealer.DHD!MTB"
        threat_id = "2147755909"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "\\Hello FBI\\source\\repos\\SoranoStealer-master\\Sorano\\obj\\Debug\\Sorano.pdb" wide //weight: 10
        $x_10_2 = "https://hokage.ru//" wide //weight: 10
        $x_10_3 = "\\\\discord\\Local Storage\\" wide //weight: 10
        $x_10_4 = "\\Applications\\MinecraftOnly\\userdata" wide //weight: 10
        $x_10_5 = "\\desktop.jpg" wide //weight: 10
        $x_1_6 = "List_Password.html" wide //weight: 1
        $x_1_7 = "\\pass.log" wide //weight: 1
        $x_1_8 = "\\CamPicture.png" wide //weight: 1
        $x_1_9 = "\\wallet.dat" wide //weight: 1
        $x_1_10 = ".docx" wide //weight: 1
        $x_1_11 = "Bitcoin" wide //weight: 1
        $x_1_12 = "\\Files\\" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 4 of ($x_1_*))) or
            ((3 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule PWS_MSIL_Stealer_DHD_2147755909_1
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/Stealer.DHD!MTB"
        threat_id = "2147755909"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/C choice /C Y /N /D Y /T 3 & Del \"" ascii //weight: 1
        $x_1_2 = "/Windows/Discord" ascii //weight: 1
        $x_1_3 = "\\BitcoinCore\\wallet.dat" ascii //weight: 1
        $x_1_4 = "\\discord\\Local Storage\\https_discordapp.com" ascii //weight: 1
        $x_1_5 = "&discord=" ascii //weight: 1
        $x_1_6 = "\\Browsers\\Passwords.txt" ascii //weight: 1
        $x_1_7 = "C:\\ProgramData\\debug.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule PWS_MSIL_Stealer_A_2147755933_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/Stealer.A!bit"
        threat_id = "2147755933"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "stealClientSide" ascii //weight: 1
        $x_1_2 = "New Discord Victem" wide //weight: 1
        $x_1_3 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_4 = "discord\\Local Storage\\https_discordapp.com_0.localstorage" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_MSIL_Stealer_MAK_2147796008_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/Stealer.MAK!MTB"
        threat_id = "2147796008"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "get_Password" ascii //weight: 1
        $x_1_2 = "set_Password" ascii //weight: 1
        $x_1_3 = "get_encryptedPassword" ascii //weight: 1
        $x_1_4 = "set_encryptedPassword" ascii //weight: 1
        $x_1_5 = "get_Username" ascii //weight: 1
        $x_1_6 = "set_Username" ascii //weight: 1
        $x_1_7 = "get_logins" ascii //weight: 1
        $x_1_8 = "set_logins" ascii //weight: 1
        $x_1_9 = "get_WebHook" ascii //weight: 1
        $x_1_10 = "set_WebHook" ascii //weight: 1
        $x_1_11 = "PassReader" ascii //weight: 1
        $x_1_12 = "ReadPasswords" ascii //weight: 1
        $x_1_13 = "SELECT * FROM AntiVirusProduct" ascii //weight: 1
        $x_1_14 = "select * from Win32_OperatingSystem" ascii //weight: 1
        $x_1_15 = "Stealer" ascii //weight: 1
        $x_1_16 = "Victim Time:" ascii //weight: 1
        $x_1_17 = "Antivirus:" ascii //weight: 1
        $x_1_18 = "Local\\Google\\Chrome\\User Data\\Default\\Login Data" ascii //weight: 1
        $x_1_19 = "SELECT action_url, username_value, password_value FROM logins" ascii //weight: 1
        $x_1_20 = "SELECT encryptedUsername, encryptedPassword, hostname FROM moz_logins" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_MSIL_Stealer_HLAY_2147813719_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/Stealer.HLAY!MTB"
        threat_id = "2147813719"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "WriteAllBytes" ascii //weight: 4
        $x_4_2 = "DownloadData" ascii //weight: 4
        $x_5_3 = "mimi.exe" wide //weight: 5
        $x_5_4 = "stderr.pl/mimi/mimikatz.exe" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_MSIL_Stealer_TLAY_2147813720_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/Stealer.TLAY!MTB"
        threat_id = "2147813720"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {07 11 06 8f 16 00 00 01 25 47 06 61 d2 52 11 06 17 58 13 06 11 06 07 8e 69 32 e5}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_MSIL_Stealer_SLID_2147814758_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/Stealer.SLID!MTB"
        threat_id = "2147814758"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "19"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {56 00 71 00 51 00 28 06 27 06 28 06 27 06 4d 00 28 06 27 06 28 06 27 06 28 06}  //weight: 1, accuracy: High
        $x_1_2 = {27 06 4b 00 66 00 68 00 77 00 28 06 27 06 28 06 27 06 28 06 27 06}  //weight: 1, accuracy: High
        $x_1_3 = {42 00 69 00 68 00 49 00 28 06 27 06 28 06 27 06 28 06 27 06 47 00 4b 00}  //weight: 1, accuracy: High
        $x_1_4 = {28 06 27 06 28 06 27 06 28 06 27 06 28 06 27 06 43 00 4b 00 43 00 45}  //weight: 1, accuracy: High
        $x_1_5 = {43 00 28 06 27 06 42 00 67 00 28 06 27 06 4a 00 44 00 77 00}  //weight: 1, accuracy: High
        $x_2_6 = "FromBase64String" ascii //weight: 2
        $x_2_7 = "Replace" ascii //weight: 2
        $x_2_8 = {00 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 00}  //weight: 2, accuracy: High
        $x_2_9 = "DTEDReader" ascii //weight: 2
        $x_2_10 = "InvokeMember" ascii //weight: 2
        $x_2_11 = "GetType" ascii //weight: 2
        $x_2_12 = {00 4b 65 79 53 70 65 63 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_MSIL_Stealer_PA10_2147899467_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/Stealer.PA10!MTB"
        threat_id = "2147899467"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "gabkauric@gmail.com" ascii //weight: 2
        $x_1_2 = "smtp.gmail.com" ascii //weight: 1
        $x_1_3 = "Y@J3jB#?LbnzNYfq" ascii //weight: 1
        $x_1_4 = "RobloxLogin__Totaly_Legit_.Properties.Resources" ascii //weight: 1
        $x_1_5 = "Login" ascii //weight: 1
        $x_1_6 = "Password:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_MSIL_Stealer_PA20_2147899468_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/Stealer.PA20!MTB"
        threat_id = "2147899468"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://bkp.myftp.org/compras/gate.php" ascii //weight: 1
        $x_1_2 = "\\ChromePasswords.txt" ascii //weight: 1
        $x_1_3 = "\\InternetExplorer\\IEPasswords.txt" ascii //weight: 1
        $x_1_4 = "Windows Web Password Credential" ascii //weight: 1
        $x_1_5 = "stealer.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

