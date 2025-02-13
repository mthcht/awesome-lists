rule Backdoor_MSIL_Pontoeb_A_2147637545_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Pontoeb.A"
        threat_id = "2147637545"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Pontoeb"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {16 0a 2b 21 7e ?? ?? ?? ?? 06 9a 6f ?? ?? ?? ?? 7e ?? ?? ?? ?? 06 9a 6f ?? ?? ?? ?? de 03 26 de 00 06 17 58 0a 06 7e ?? ?? ?? ?? 32 d7 2a 00}  //weight: 5, accuracy: Low
        $x_1_2 = "mode=0&hwid=" wide //weight: 1
        $x_1_3 = {6e 55 44 50 46 6c 6f 6f 64 00}  //weight: 1, accuracy: High
        $x_1_4 = {6e 53 59 4e 46 6c 6f 6f 64 00}  //weight: 1, accuracy: High
        $x_1_5 = {6e 49 43 4d 50 46 6c 6f 6f 64 00}  //weight: 1, accuracy: High
        $x_1_6 = {6e 48 54 54 50 46 6c 6f 6f 64 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_MSIL_Pontoeb_A_2147637744_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Pontoeb.gen!A"
        threat_id = "2147637744"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Pontoeb"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "150"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {2f 00 62 00 6f 00 74 00 2e 00 70 00 68 00 70 00 3f 00 68 00 77 00 69 00 64 00 3d 00 [0-6] 70 00 63 00 6e 00 61 00 6d 00 65 00 3d 00 [0-3] 26 00 61 00 6e 00 74 00 77 00 6f 00 72 00 74 00 3d 00}  //weight: 100, accuracy: Low
        $x_50_2 = {42 6f 74 5c 53 65 72 76 65 72 5c 53 79 73 44 72 69 76 65 72 5c 6f 62 6a 5c 78 38 36 5c 52 65 6c 65 61 73 65 5c 53 79 73 44 72 69 76 65 72 2e 70 64 62 00}  //weight: 50, accuracy: High
        $x_50_3 = "\\Stub\\bot_clean\\obj\\Release\\" ascii //weight: 50
        $x_10_4 = "SELECT * FROM Win32_VideoController" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 1 of ($x_50_*))) or
            (all of ($x*))
        )
}

rule Backdoor_MSIL_Pontoeb_A_2147637744_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Pontoeb.gen!A"
        threat_id = "2147637744"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Pontoeb"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "100"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {02 8e b7 17 da 0b 2b 29 02 07 02 07 91 03 07 03 8e b7 5d 91 61 02 07 17 d6 02 8e b7 5d 91 da 20 00 01 00 00 d6 20 00 01 00 00 5d b4 9c 07 15 d6 0b 07 16 2f d3 02 2a}  //weight: 10, accuracy: High
        $x_10_2 = {02 1f 3c 28 e5 00 00 0a 13 06 02 11 06 1c d6 28 e6 00 00 0a 13 05 12 0a 02 11 06 1f 54 d6 28 e5 00 00 0a 28 e7 00 00 0a 1f 44 8d 72 00 00 01 13}  //weight: 10, accuracy: High
        $x_100_3 = {53 65 74 74 69 6e 67 73 5c 4e 61 74 68 75 20 53 69 6b 61 6e 64 61 72 5c 44 65 73 6b 74 6f 70 5c 56 33 53 45 5c 56 33 53 45 5c 6f 62 6a 5c 52 65 6c 65 61 73 65 5c 56 33 53 45 2e 70 64 62 00 00}  //weight: 100, accuracy: High
        $x_5_4 = "SELECT * FROM Win32_VideoController" wide //weight: 5
        $x_5_5 = "sc.exe config AntiVirService start= disabled" wide //weight: 5
        $x_5_6 = "\\Eset\\ESET NOD32 Antivirus\\*.exe*" wide //weight: 5
        $x_5_7 = "\\avira\\antivir desktop\\\\*.dll*" wide //weight: 5
        $x_1_8 = "HKEY_LOCAL_MACHINE\\SOFTWARE\\LimeWire\\" wide //weight: 1
        $x_1_9 = "porn_vids_part1.scr" wide //weight: 1
        $x_1_10 = "iBangPornstars.scr" wide //weight: 1
        $x_1_11 = "stoning_video.scr" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*))) or
            (all of ($x*))
        )
}

rule Backdoor_MSIL_Pontoeb_B_2147639626_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Pontoeb.B"
        threat_id = "2147639626"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Pontoeb"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {49 6e 73 74 61 6c 6c 42 6f 74 00 75 70 64 61 74 65 42 6f 74 00 52 65 6d 6f 76 65 42 6f 74 00}  //weight: 1, accuracy: High
        $x_1_2 = "&botver=" wide //weight: 1
        $x_1_3 = "SELECT * FROM Win32_BaseBoard" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Pontoeb_J_2147652524_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Pontoeb.J"
        threat_id = "2147652524"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Pontoeb"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "77.79.4.101/" ascii //weight: 1
        $x_1_2 = "Windows-Audio Driver" wide //weight: 1
        $x_1_3 = "Windows-Network Component" wide //weight: 1
        $x_1_4 = "SELECT * FROM Win32_BaseBoard" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Pontoeb_N_2147655911_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Pontoeb.N"
        threat_id = "2147655911"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Pontoeb"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/gate.php" wide //weight: 1
        $x_1_2 = "wscntfy.exe" wide //weight: 1
        $x_1_3 = "lsmass.exe" wide //weight: 1
        $x_1_4 = "Windows-Audio Driver" wide //weight: 1
        $x_1_5 = "Windows-Network Component" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

