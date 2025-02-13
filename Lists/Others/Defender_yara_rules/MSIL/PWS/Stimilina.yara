rule PWS_MSIL_Stimilina_A_2147694385_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/Stimilina.A"
        threat_id = "2147694385"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stimilina"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "config.vdf" wide //weight: 2
        $x_2_2 = "steal" wide //weight: 2
        $x_5_3 = "ssfn*" ascii //weight: 5
        $x_4_4 = "smtp.mail.ru" wide //weight: 4
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule PWS_MSIL_Stimilina_A_2147694385_1
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/Stimilina.A"
        threat_id = "2147694385"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stimilina"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "ssfn*" ascii //weight: 2
        $x_2_2 = "config.vdf" wide //weight: 2
        $x_2_3 = "steal" wide //weight: 2
        $x_3_4 = "185.28.20.99" ascii //weight: 3
        $x_3_5 = "31.220.16.110" ascii //weight: 3
        $x_3_6 = "185.28.20.83" ascii //weight: 3
        $x_3_7 = "31.220.16.28" ascii //weight: 3
        $x_3_8 = {74 00 73 00 65 00 63 00 72 00 65 00 74 00 34 00 36 00 37 00 [0-32] 40 00 67 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00}  //weight: 3, accuracy: Low
        $x_3_9 = {74 73 65 63 72 65 74 34 36 37 [0-32] 40 67 6d 61 69 6c 2e 63 6f 6d}  //weight: 3, accuracy: Low
        $x_3_10 = "jrrxQiSIZ4RTmKq@mail.ru" ascii //weight: 3
        $x_3_11 = "hezgovy1vuxf0@mail.ru" ascii //weight: 3
        $x_3_12 = "stealerbyframe@mail.ru" ascii //weight: 3
        $x_3_13 = "mrframe59@gmail.com" ascii //weight: 3
        $x_3_14 = "stilletmajloy228@mail.ru" ascii //weight: 3
        $x_3_15 = "kparnak@mail.ru" ascii //weight: 3
        $x_3_16 = "avangard.mansur@mail.ru" ascii //weight: 3
        $x_3_17 = "mansur2@mail.ua" ascii //weight: 3
        $x_3_18 = "stealer228@mail.ua" ascii //weight: 3
        $x_3_19 = "Vulfbrut@mail.ru" ascii //weight: 3
        $x_3_20 = "dota2tourname@mail.ru" ascii //weight: 3
        $x_3_21 = "aaassseedf@mail.ru" ascii //weight: 3
        $x_3_22 = "loloyfvfyv@mail.ru" ascii //weight: 3
        $x_3_23 = "radik.taraska@mail.ru" ascii //weight: 3
        $x_3_24 = "dmuvka@mail.ru" ascii //weight: 3
        $x_3_25 = "fan.avan@mail.ru" ascii //weight: 3
        $x_3_26 = "fannik.navi@mail.ru" ascii //weight: 3
        $x_3_27 = "stealler228@inbox.ru" ascii //weight: 3
        $x_3_28 = "vlad123456789999@mail.ru" ascii //weight: 3
        $x_3_29 = "korobitsyn1999@mail.ru" ascii //weight: 3
        $x_3_30 = "majloysteal228@mail.ru" ascii //weight: 3
        $x_3_31 = "mansur1996mansur2@mail.ua?dimono50" ascii //weight: 3
        $x_3_32 = "niko23577@gmail.com" ascii //weight: 3
        $x_3_33 = "petya-pupkin-pupkin@inbox.ru" ascii //weight: 3
        $x_3_34 = "rust.rust.84@mail.ru" ascii //weight: 3
        $x_3_35 = "solek567@mail.ru" ascii //weight: 3
        $x_3_36 = "stealerbymajloy@mail.ru" ascii //weight: 3
        $x_3_37 = "stealermajloy1488@mail.ru" ascii //weight: 3
        $x_3_38 = "stiller.maloy228@mail.ru" ascii //weight: 3
        $x_3_39 = "stiller46@mail.ru" ascii //weight: 3
        $x_3_40 = "bhdsbc@mail.ru" ascii //weight: 3
        $x_3_41 = "Vulfbruttt@mail.ru" ascii //weight: 3
        $x_3_42 = "yvp_fyp@mail.ru" ascii //weight: 3
        $x_3_43 = "sadlasdll@mail.ru" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 2 of ($x_2_*))) or
            ((2 of ($x_3_*) and 1 of ($x_2_*))) or
            ((3 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule PWS_MSIL_Stimilina_B_2147694649_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/Stimilina.B"
        threat_id = "2147694649"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stimilina"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run\\" ascii //weight: 1
        $x_1_2 = {73 00 63 00 72 00 65 00 65 00 6e 00 73 00 68 00 6f 00 74 00 5f 00 [0-6] 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_3 = {73 63 72 65 65 6e 73 68 6f 74 5f [0-6] 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_4 = "iconcachedb.exe" ascii //weight: 1
        $x_1_5 = "\\LocalService.exe" wide //weight: 1
        $x_2_6 = "//pic-screenshot.com/" wide //weight: 2
        $x_2_7 = {2f 00 2f 00 73 00 65 00 6e 00 64 00 2d 00 69 00 6d 00 61 00 67 00 65 00 2e 00 75 00 73 00 2f 00 [0-16] 2e 00 70 00 68 00 70 00 3f 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_MSIL_Stimilina_B_2147694649_1
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/Stimilina.B"
        threat_id = "2147694649"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stimilina"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run\\" ascii //weight: 1
        $x_1_2 = {73 00 63 00 72 00 65 00 65 00 6e 00 73 00 68 00 6f 00 74 00 5f 00 [0-6] 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_3 = {73 63 72 65 65 6e 73 68 6f 74 5f [0-6] 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_4 = "iconcachedb.exe" ascii //weight: 1
        $x_2_5 = "//image4you.us/" wide //weight: 2
        $x_2_6 = {2f 00 2f 00 69 00 6d 00 61 00 67 00 65 00 2d 00 70 00 6e 00 67 00 2e 00 75 00 73 00 2f 00 [0-16] 2e 00 70 00 68 00 70 00}  //weight: 2, accuracy: Low
        $x_4_7 = {74 00 73 00 65 00 63 00 72 00 65 00 74 00 34 00 36 00 37 00 [0-16] 40 00 67 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00}  //weight: 4, accuracy: Low
        $x_4_8 = {74 73 65 63 72 65 74 34 36 37 [0-16] 40 67 6d 61 69 6c 2e 63 6f 6d}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_2_*))) or
            ((2 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule PWS_MSIL_Stimilina_C_2147694676_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/Stimilina.C"
        threat_id = "2147694676"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stimilina"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/gate_new.php" wide //weight: 1
        $x_3_2 = "ssfn*" ascii //weight: 3
        $x_3_3 = "SteamStealer" ascii //weight: 3
        $x_3_4 = "SteamWorker" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_MSIL_Stimilina_C_2147694676_1
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/Stimilina.C"
        threat_id = "2147694676"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stimilina"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "steam.exe\" \"%1\"" ascii //weight: 2
        $x_2_2 = "\\SteamAppData.vdf" ascii //weight: 2
        $x_2_3 = "\\loginusers.vdf" ascii //weight: 2
        $x_3_4 = "\\Steam Core\\.src visur\\" ascii //weight: 3
        $x_8_5 = "ssfn*" ascii //weight: 8
        $x_11_6 = "//csgolounuge.org/" wide //weight: 11
        $x_12_7 = "authuser=0&id=0BzhWe_qK75wNUHd6SXlfS09UakU&export=download" wide //weight: 12
        $x_12_8 = "//files.sellexpo.net/" wide //weight: 12
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_8_*) and 3 of ($x_2_*))) or
            ((1 of ($x_8_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_11_*) and 1 of ($x_2_*))) or
            ((1 of ($x_11_*) and 1 of ($x_3_*))) or
            ((1 of ($x_11_*) and 1 of ($x_8_*))) or
            ((1 of ($x_12_*) and 1 of ($x_2_*))) or
            ((1 of ($x_12_*) and 1 of ($x_3_*))) or
            ((1 of ($x_12_*) and 1 of ($x_8_*))) or
            ((1 of ($x_12_*) and 1 of ($x_11_*))) or
            ((2 of ($x_12_*))) or
            (all of ($x*))
        )
}

rule PWS_MSIL_Stimilina_D_2147694726_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/Stimilina.D"
        threat_id = "2147694726"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stimilina"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "/data/entry/ssfn.php" wide //weight: 5
        $x_1_2 = "Steam needs to be online to update. Please wait restarting the steam." wide //weight: 1
        $x_1_3 = "Steam - Fatal Error" wide //weight: 1
        $x_2_4 = "127.0.0.1 store.steampowered.com" wide //weight: 2
        $x_2_5 = "127.0.0.1 steamcommunity.com" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 2 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule PWS_MSIL_Stimilina_D_2147694726_1
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/Stimilina.D"
        threat_id = "2147694726"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stimilina"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Steam needs to be online to update. Please wait restarting the steam." wide //weight: 1
        $x_1_2 = "Steam - Fatal Error" wide //weight: 1
        $x_2_3 = "ssfn*" ascii //weight: 2
        $x_2_4 = "127.0.0.1 store.steampowered.com" wide //weight: 2
        $x_2_5 = "127.0.0.1 steamcommunity.com" wide //weight: 2
        $x_4_6 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f [0-48] 2f [0-48] 2e 00 70 00 68 00 70 00 02 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 2f [0-48] 2f 00 73 00 74 00 65 00 61 00 6d 00 2e 00 65 00 78 00 65}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule PWS_MSIL_Stimilina_E_2147694854_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/Stimilina.E"
        threat_id = "2147694854"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stimilina"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\config\\" wide //weight: 1
        $x_1_2 = "*.vdf" wide //weight: 1
        $x_2_3 = "ftp://{0}" wide //weight: 2
        $x_2_4 = "ssfn*" wide //weight: 2
        $x_5_5 = {8d 07 00 00 01 13 06 11 06 16 1f 2f 9d 11 06 6f 06 00 00 0a 0c 72 ?? ?? 00 70 03 28 07 00 00 0a 0d 08 13 07 16 13 08}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_MSIL_Stimilina_F_2147697216_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/Stimilina.F"
        threat_id = "2147697216"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stimilina"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "cp/upload_browser.php" wide //weight: 1
        $x_1_2 = "/cp/logs_print.php" wide //weight: 1
        $x_1_3 = "/cp/upload_get.php" wide //weight: 1
        $x_2_4 = {0f 73 00 73 00 66 00 6e 00 2a 00 2e 00 2a 00 00 09 2e 00 74 00 65 00 74 00 00}  //weight: 2, accuracy: High
        $x_2_5 = {2f 00 63 00 70 00 2f 00 6c 00 6f 00 67 00 73 00 5f 00 70 00 72 00 69 00 6e 00 74 00 2e 00 70 00 68 00 70 00 3f 00 73 00 69 00 64 00 3d 00 73 00 74 00 65 00 61 00 6d 00 [0-4] 26 00 6d 00 3d 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule PWS_MSIL_Stimilina_G_2147706592_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/Stimilina.G"
        threat_id = "2147706592"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stimilina"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AllSavedProfiles.txt" wide //weight: 1
        $x_1_2 = "AllPasswords.txt" wide //weight: 1
        $x_1_3 = "On Copie MultiPasswords" wide //weight: 1
        $x_1_4 = "SendBrowserPasswords" wide //weight: 1
        $x_1_5 = "StealConfigsSsfnBPasswords" wide //weight: 1
        $x_1_6 = "Retrieve Steam Account" wide //weight: 1
        $x_1_7 = "message\":\"SteamGuard" wide //weight: 1
        $x_1_8 = "steamid\":\"(.*?)\"" wide //weight: 1
        $x_1_9 = "Steam Login" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule PWS_MSIL_Stimilina_H_2147706818_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/Stimilina.H"
        threat_id = "2147706818"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stimilina"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 00 53 00 74 00 65 00 61 00 6d 00 2e 00 65 00 78 00 65 00 ?? ?? 5c 00 64 00 72 00 69 00 76 00 65 00 72 00 73 00 5c 00 65 00 74 00 63 00 5c 00 68 00 6f 00 73 00 74 00 73 00}  //weight: 1, accuracy: Low
        $x_1_2 = "127.0.0.1 steamcommunity.com" wide //weight: 1
        $x_1_3 = "127.0.0.1 yandex.ru" wide //weight: 1
        $x_1_4 = {6c 00 6f 00 67 00 69 00 6e 00 73 00 ?? ?? 6f 00 72 00 69 00 67 00 69 00 6e 00 5f 00 75 00 72 00 6c 00 [0-96] 75 00 73 00 65 00 72 00 6e 00 61 00 6d 00 65 00 5f 00 76 00 61 00 6c 00 75 00 65 00 ?? ?? 70 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 5f 00 76 00 61 00 6c 00 75 00 65 00}  //weight: 1, accuracy: Low
        $x_1_5 = "/data/entry/data.php" wide //weight: 1
        $x_1_6 = "\\Opera\\wand.dat" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_MSIL_Stimilina_I_2147707030_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/Stimilina.I"
        threat_id = "2147707030"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stimilina"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "45"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "StealConfigsSsfnBPasswords" wide //weight: 20
        $x_20_2 = "/config/SteamAppData.vdf" wide //weight: 20
        $x_1_3 = "AllSavedProfiles.txt" wide //weight: 1
        $x_1_4 = "AllPasswords.txt" wide //weight: 1
        $x_1_5 = "On Copie MultiPasswords" wide //weight: 1
        $x_1_6 = "On Copie MultiCookies" wide //weight: 1
        $x_1_7 = "SendBrowserPasswords" wide //weight: 1
        $x_1_8 = "BrowserPasswords.zip" wide //weight: 1
        $x_1_9 = "GrabTxtOnDeskTop" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_20_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_MSIL_Stimilina_N_2147707782_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/Stimilina.N"
        threat_id = "2147707782"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stimilina"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SteamFakeClient" ascii //weight: 1
        $x_1_2 = "{3}Link: {2}{3}Username: {0}{3}Password: {1}{3}" wide //weight: 1
        $x_1_3 = "StealConfigsSsfnBPasswords" wide //weight: 1
        $x_1_4 = "SendBrowserPasswords" wide //weight: 1
        $x_1_5 = "On Copie MultiPasswords" wide //weight: 1
        $x_1_6 = ": form-data; name=\"{1}\"; filename=\"{2}\";" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule PWS_MSIL_Stimilina_O_2147712060_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/Stimilina.O!bit"
        threat_id = "2147712060"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stimilina"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "URL: {1}{0}Username: {2}{0}Pqssword: {3}{0}" wide //weight: 1
        $x_1_2 = "Coool software" wide //weight: 1
        $x_1_3 = "StartKeyLogger" wide //weight: 1
        $x_1_4 = "StealerReborn" wide //weight: 1
        $x_1_5 = "ssfn*" wide //weight: 1
        $x_1_6 = "Report.jfl" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_MSIL_Stimilina_Q_2147719008_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/Stimilina.Q!bit"
        threat_id = "2147719008"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stimilina"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = "steam.exe\" \"%1\"" ascii //weight: 3
        $x_3_2 = "ssfn*" ascii //weight: 3
        $x_3_3 = {73 00 65 00 72 00 76 00 69 00 63 00 65 00 6d 00 61 00 6e 00 33 00 33 00 2e 00 72 00 75 00 2f 00 [0-32] 2e 00 61 00 73 00 70 00 78 00 [0-16] 69 00 64 00 3d 00 [0-16] 26 00 74 00 79 00 70 00 65 00 3d 00 61 00 64 00 64 00 6c 00 6f 00 67 00 26 00 74 00 65 00 78 00 74 00 3d 00}  //weight: 3, accuracy: Low
        $x_2_4 = {5c 00 4f 00 70 00 65 00 72 00 61 00 5c 00 4f 00 70 00 65 00 72 00 61 00 [0-32] 5c 00 77 00 61 00 6e 00 64 00 2e 00 64 00 61 00 74 00}  //weight: 2, accuracy: Low
        $x_2_5 = "win32_logicaldisk.deviceid=" wide //weight: 2
        $x_1_6 = "Opera Software\\Opera Stable\\Login Data" wide //weight: 1
        $x_1_7 = "Google\\Chrome\\User Data\\Default\\Login Data" wide //weight: 1
        $x_1_8 = "Yandex\\YandexBrowser\\User Data\\Default\\Login Data" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_3_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_3_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_MSIL_Stimilina_P_2147719016_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/Stimilina.P!bit"
        threat_id = "2147719016"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stimilina"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 50 00 6f 00 6c 00 69 00 63 00 69 00 65 00 73 00 5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 [0-16] 45 00 6e 00 61 00 62 00 6c 00 65 00 4c 00 55 00 41 00}  //weight: 1, accuracy: Low
        $x_1_2 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_3 = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v DisableTaskMgr /t REG_DWORD /d" wide //weight: 1
        $x_1_4 = {48 00 4b 00 45 00 59 00 5f 00 4c 00 4f 00 43 00 41 00 4c 00 5f 00 4d 00 41 00 43 00 48 00 49 00 4e 00 45 00 5c 00 53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20 00 4e 00 54 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 52 00 65 00 73 00 74 00 6f 00 72 00 65 00 [0-16] 44 00 69 00 73 00 61 00 62 00 6c 00 65 00 53 00 52 00}  //weight: 1, accuracy: Low
        $x_1_5 = "Google\\Chrome\\User Data\\Default\\Login Data" wide //weight: 1
        $x_1_6 = "Yandex\\YandexBrowser\\User Data\\Default\\Login Data" wide //weight: 1
        $x_1_7 = {6c 00 6f 00 67 00 69 00 6e 00 73 00 ?? ?? 6f 00 72 00 69 00 67 00 69 00 6e 00 5f 00 75 00 72 00 6c 00 [0-96] 75 00 73 00 65 00 72 00 6e 00 61 00 6d 00 65 00 5f 00 76 00 61 00 6c 00 75 00 65 00 ?? ?? 70 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 5f 00 76 00 61 00 6c 00 75 00 65 00}  //weight: 1, accuracy: Low
        $x_1_8 = "Shutdown -r -t" wide //weight: 1
        $x_1_9 = "PK11SDR_Decrypt" wide //weight: 1
        $x_1_10 = "encryptedPassword" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule PWS_MSIL_Stimilina_R_2147722624_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/Stimilina.R!bit"
        threat_id = "2147722624"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stimilina"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "690CEFE15B853F35A429B884DC3402A022918213" ascii //weight: 1
        $x_1_2 = "D583C75FD06863D084AD345218B53FDD826FC46D" ascii //weight: 1
        $x_1_3 = "F016ABBA763E33BD56971284BC3E61911410DBCF" ascii //weight: 1
        $x_1_4 = {54 6f 42 61 73 65 36 34 53 74 72 69 6e 67 00 43 72 65 61 74 65 45 6e 63 72 79 70 74 6f 72 00 43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

