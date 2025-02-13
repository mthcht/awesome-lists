rule TrojanDownloader_MSIL_Genmaldow_N_2147708624_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Genmaldow.N"
        threat_id = "2147708624"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Genmaldow"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {09 11 06 09 11 06 91 04 61 d2 9c 11 06 17 58}  //weight: 1, accuracy: High
        $x_1_2 = {02 03 61 0c 08 1f 11 5a 1f 1b 5b 0c 07 1d 08 58}  //weight: 1, accuracy: High
        $x_1_3 = {69 64 6f 74 6b 6e 6f 77 2e 65 78 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Genmaldow_Q_2147710504_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Genmaldow.Q"
        threat_id = "2147710504"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Genmaldow"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 [0-16] 2e 00 67 00 65 00 2e 00 74 00 74 00 2f 00 [0-64] 2f 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 41 00 70 00 70 00 6c 00 69 00 63 00 61 00 74 00 69 00 6f 00 6e 00 ?? ?? 2e 00 65 00 78 00 65 00 3f 00 69 00 6e 00 64 00 65 00 78 00 3d 00 [0-4] 26 00 75 00 73 00 65 00 72 00 3d 00 75 00 73 00 65 00 72 00 2d 00}  //weight: 1, accuracy: Low
        $x_1_2 = {26 00 64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 3d 00 ?? ?? 74 00 65 00 6d 00 70 00 ?? ?? 2f 00 [0-16] 2e 00 45 00 78 00 45 00}  //weight: 1, accuracy: Low
        $x_1_3 = ".NET Reactor" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Genmaldow_S_2147711699_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Genmaldow.S"
        threat_id = "2147711699"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Genmaldow"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 00 4c 00 45 00 45 00 50 00 48 00 49 00 44 00 45 00 [0-32] 2e 00 65 00 78 00 65 00 ?? ?? 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00}  //weight: 1, accuracy: Low
        $x_1_2 = {26 00 65 00 78 00 70 00 6f 00 72 00 74 00 3d 00 64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 ?? ?? 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 [0-64] 2e 00 70 00 68 00 70 00 3f 00 65 00 78 00 3d 00 [0-32] 74 00 61 00 73 00 6b 00 68 00 6f 00 73 00 74 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Genmaldow_S_2147711699_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Genmaldow.S"
        threat_id = "2147711699"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Genmaldow"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 6d 00 79 00 2d 00 73 00 61 00 76 00 65 00 2d 00 69 00 6d 00 67 00 2e 00 72 00 75 00 2f 00 69 00 70 00 32 00 2e 00 70 00 68 00 70 00 [0-32] 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 6d 00 79 00 2d 00 73 00 61 00 76 00 65 00 2d 00 69 00 6d 00 67 00 2e 00 72 00 75 00 2f 00 [0-16] 2e 00 6a 00 70 00 67 00}  //weight: 5, accuracy: Low
        $x_1_2 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 64 00 6f 00 63 00 73 00 2e 00 67 00 6f 00 6f 00 67 00 6c 00 65 00 2e 00 63 00 6f 00 6d 00 2f 00 75 00 63 00 [0-128] 26 00 65 00 78 00 70 00 6f 00 72 00 74 00 3d 00 64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Genmaldow_T_2147711708_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Genmaldow.T"
        threat_id = "2147711708"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Genmaldow"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {49 6e 76 6f 69 63 65 20 23 [0-10] 2e 65 78 65}  //weight: 3, accuracy: Low
        $x_1_2 = "_AddRegistry" ascii //weight: 1
        $x_1_3 = "DownloadFileFTP" ascii //weight: 1
        $x_1_4 = "export=download&id=" wide //weight: 1
        $x_1_5 = "\\system files\\" wide //weight: 1
        $x_1_6 = "Sub_main.exe" wide //weight: 1
        $x_1_7 = "HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_3_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_MSIL_Genmaldow_U_2147716251_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Genmaldow.U"
        threat_id = "2147716251"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Genmaldow"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".Replace(\" \", \"\").Replace(\"\\\\n\", \"\").Split('|');" ascii //weight: 1
        $x_1_2 = "Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), \"Java\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Genmaldow_V_2147719476_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Genmaldow.V"
        threat_id = "2147719476"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Genmaldow"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {41 64 64 54 6f 53 74 61 72 74 75 70 [0-16] 48 69 64 65 46 69 6c 65}  //weight: 5, accuracy: Low
        $x_2_2 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 [0-16] 43 00 72 00 79 00 70 00 74 00 65 00 64 00 46 00 69 00 6c 00 65 00}  //weight: 2, accuracy: Low
        $x_1_3 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 75 00 70 00 6c 00 6f 00 61 00 64 00 34 00 66 00 72 00 65 00 65 00 2e 00 78 00 79 00 7a 00 2f 00 6c 00 6e 00 6b 00 2e 00 [0-32] 2e 00 6c 00 6e 00 6b 00}  //weight: 1, accuracy: Low
        $x_1_4 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 [0-48] 2f 00 6c 00 6e 00 6b 00 2e 00 77 00 73 00 63 00 [0-8] 5c 00 77 00 73 00 63 00 2e 00 6c 00 6e 00 6b 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_MSIL_Genmaldow_W_2147735436_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Genmaldow.W"
        threat_id = "2147735436"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Genmaldow"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Users\\Roock\\source\\repos\\Revivel\\Revivel\\obj\\Release" ascii //weight: 1
        $x_1_2 = "v2.0.50727" ascii //weight: 1
        $x_1_3 = "RealAndGood" ascii //weight: 1
        $x_1_4 = "ObieTrice" ascii //weight: 1
        $x_1_5 = "SlowerGodl" ascii //weight: 1
        $x_1_6 = "StopMaking" ascii //weight: 1
        $x_1_7 = "Rabat" ascii //weight: 1
        $x_1_8 = "Flesh" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

