rule TrojanDownloader_MSIL_Gendwnurl_B_2147717183_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Gendwnurl.B!bit"
        threat_id = "2147717183"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Gendwnurl"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {06 08 03 07 17 28 ?? 00 00 0a 28 ?? 00 00 0a 61 28 ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a 0a 00 07 17 58 b5}  //weight: 1, accuracy: Low
        $x_1_2 = "DownloadFile" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Gendwnurl_F_2147717742_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Gendwnurl.F!bit"
        threat_id = "2147717742"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Gendwnurl"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {07 09 03 08 17 28 ?? 00 00 0a 28 ?? 00 00 0a 61 28 ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a 0b 00 08 17 58 b5 0c}  //weight: 1, accuracy: Low
        $x_1_2 = "DownloadFile" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Gendwnurl_H_2147718551_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Gendwnurl.H!bit"
        threat_id = "2147718551"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Gendwnurl"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2f 00 2f 00 64 00 6c 00 2e 00 64 00 72 00 6f 00 70 00 62 00 6f 00 78 00 2e 00 63 00 6f 00 6d 00 2f 00 73 00 2f 00 [0-31] 2f 00 73 00 69 00 74 00 68 00 69 00 64 00 64 00 65 00 6e 00 2e 00 74 00 78 00 74 00}  //weight: 1, accuracy: Low
        $x_1_2 = "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_3 = "lab.soft1@gmail.com" wide //weight: 1
        $x_1_4 = "\\data\\ieclone.mdb;User Id=admin;Password=;" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Gendwnurl_L_2147718819_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Gendwnurl.L!bit"
        threat_id = "2147718819"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Gendwnurl"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {64 00 6f 00 63 00 73 00 2e 00 67 00 6f 00 6f 00 67 00 6c 00 65 00 2e 00 63 00 6f 00 6d 00 2f 00 75 00 63 00 3f 00 69 00 64 00 3d 00 [0-63] 26 00 65 00 78 00 70 00 6f 00 72 00 74 00 3d 00 64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00}  //weight: 1, accuracy: Low
        $x_1_2 = "/isss.php?id=" wide //weight: 1
        $x_1_3 = "&type=addlog&text=started" wide //weight: 1
        $x_1_4 = "taskhostex" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Gendwnurl_AX_2147721921_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Gendwnurl.AX!bit"
        threat_id = "2147721921"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Gendwnurl"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "jddrtj.duckdns.org/vitp/index.php?nome=" wide //weight: 1
        $x_1_2 = "BTC GENERATOR_" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Gendwnurl_BC_2147722713_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Gendwnurl.BC!bit"
        threat_id = "2147722713"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Gendwnurl"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {1b 5c 00 6e 00 76 00 78 00 64 00 73 00 79 00 6e 00 63 00 2e 00 65 00 78 00 65 00 00 ?? 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00}  //weight: 1, accuracy: Low
        $x_1_2 = {11 6e 00 76 00 78 00 64 00 73 00 79 00 6e 00 63 00 00 77 48 00 4b 00 45 00 59 00 5f 00 43 00 55 00 52 00 52 00 45 00 4e 00 54 00 5f 00 55 00 53 00 45 00 52 00 5c 00 53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 43 00 6c 00 61 00 73 00 73 00 65 00 73 00 5c 00 73 00 74 00 65 00 61 00 6d 00 5c 00 53 00 68 00 65 00 6c 00 6c 00 5c 00 4f 00 70 00 65 00 6e 00 5c 00 43 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Gendwnurl_BC_2147722713_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Gendwnurl.BC!bit"
        threat_id = "2147722713"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Gendwnurl"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "56546fff" wide //weight: 1
        $x_1_2 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 73 00 61 00 76 00 65 00 69 00 6d 00 61 00 67 00 65 00 2e 00 70 00 77 00 [0-32] 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_3 = "HKEY_CURRENT_USER\\Software\\Classes\\steam\\Shell\\Open\\Command" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Gendwnurl_AY_2147722750_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Gendwnurl.AY!bit"
        threat_id = "2147722750"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Gendwnurl"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "WshShell.Run \"cmd /c bitsadmin /transfer /download /priority high" wide //weight: 1
        $x_1_2 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 6d 00 61 00 6e 00 61 00 67 00 65 00 31 00 6c 00 6e 00 6b 00 2e 00 70 00 77 00 [0-48] 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_3 = "start WEscr.vbs" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Gendwnurl_AZ_2147722751_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Gendwnurl.AZ!bit"
        threat_id = "2147722751"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Gendwnurl"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "2hd2jd8fh" wide //weight: 1
        $x_1_2 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 70 00 69 00 63 00 2d 00 70 00 69 00 63 00 2e 00 70 00 77 00 [0-32] 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_3 = "HKEY_CURRENT_USER\\Software\\Classes\\steam\\Shell\\Open\\Command" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Gendwnurl_BD_2147722781_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Gendwnurl.BD!bit"
        threat_id = "2147722781"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Gendwnurl"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "vipmanworld0123456789" wide //weight: 1
        $x_2_2 = "/C rd /s /q %temp%" wide //weight: 2
        $x_1_3 = "5c5c576f77363433324e6f64655c5c4d6963726f736f66745c5c57696e646f77735c5c43757272656e7456657273696f6e5c5c52756e" wide //weight: 1
        $x_1_4 = "536f6674776172655c5c4d6963726f736f66745c5c57696e646f77735c5c43757272656e7456657273696f6e5c5c52756e" wide //weight: 1
        $x_1_5 = "2f6766696c65732e706870" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_MSIL_Gendwnurl_BA_2147723101_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Gendwnurl.BA!bit"
        threat_id = "2147723101"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Gendwnurl"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 69 00 6d 00 61 00 67 00 65 00 73 00 2d 00 73 00 61 00 76 00 65 00 72 00 2e 00 70 00 77 00 2f 00 [0-48] 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_2 = "HKEY_CURRENT_USER\\Software\\Classes\\steam\\Shell\\Open\\Command" wide //weight: 1
        $x_1_3 = {57 65 62 43 6c 69 65 6e 74 00 53 79 73 74 65 6d 2e 4e 65 74 00 44 6f 77 6e 6c 6f 61 64 46 69 6c 65}  //weight: 1, accuracy: High
        $x_1_4 = {4d 75 74 65 78 00 53 79 73 74 65 6d 2e 54 68 72 65 61 64 69 6e 67}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Gendwnurl_BE_2147724798_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Gendwnurl.BE!bit"
        threat_id = "2147724798"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Gendwnurl"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "jbdsicoio" wide //weight: 1
        $x_1_2 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 69 00 6d 00 67 00 2d 00 73 00 61 00 76 00 65 00 2e 00 78 00 79 00 7a 00 [0-32] 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_3 = "HKEY_CURRENT_USER\\Software\\Classes\\steam\\Shell\\Open\\Command" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Gendwnurl_BJ_2147724799_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Gendwnurl.BJ!bit"
        threat_id = "2147724799"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Gendwnurl"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 34 00 37 00 2e 00 38 00 39 00 2e 00 31 00 38 00 37 00 2e 00 35 00 34 00 [0-32] 2e 00 72 00 61 00 72 00 20 00 43 00 3a 00 5c 00 54 00 45 00 4d 00 50 00 [0-16] 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_2 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_3 = "/k DownloadFile" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Gendwnurl_BK_2147724800_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Gendwnurl.BK!bit"
        threat_id = "2147724800"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Gendwnurl"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 74 74 70 3a 2f 2f 63 6b 70 65 74 63 68 65 6d 2e 63 6f 6d [0-16] 2e 74 78 74}  //weight: 1, accuracy: Low
        $x_1_2 = {6c 00 6f 00 61 00 64 00 [0-16] 65 00 6e 00 74 00 72 00 79 00 70 00 6f 00 69 00 6e 00 74 00 [0-16] 69 00 6e 00 76 00 6f 00 6b 00 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Gendwnurl_BL_2147725700_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Gendwnurl.BL!bit"
        threat_id = "2147725700"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Gendwnurl"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "screenshot" wide //weight: 1
        $x_1_2 = "systeminfo" wide //weight: 1
        $x_1_3 = "http://c2.howielab.com/C2/Command" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Gendwnurl_BM_2147725701_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Gendwnurl.BM!bit"
        threat_id = "2147725701"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Gendwnurl"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "C:\\Windows\\Temp\\" wide //weight: 1
        $x_1_2 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 6d 00 6f 00 6e 00 65 00 63 00 6f 00 6d 00 2e 00 64 00 64 00 6e 00 73 00 2e 00 6e 00 65 00 74 00 [0-16] 2e 00 7a 00 69 00 70 00}  //weight: 1, accuracy: Low
        $x_1_3 = "Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Gendwnurl_BO_2147727773_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Gendwnurl.BO!bit"
        threat_id = "2147727773"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Gendwnurl"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 00 74 00 74 00 70 00 3a 00 [0-32] 2e 00 70 00 77 00 2f 00 69 00 70 00 32 00 2e 00 70 00 68 00 70 00 3f 00 65 00 78 00 3d 00}  //weight: 1, accuracy: Low
        $x_1_2 = "SteamService.exe" wide //weight: 1
        $x_1_3 = "923f329yf9" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Gendwnurl_BO_2147727773_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Gendwnurl.BO!bit"
        threat_id = "2147727773"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Gendwnurl"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "IEX (New-Object Net.WebClient).DownloadString('http" wide //weight: 1
        $x_1_2 = ".jpg'); hackbacktrack" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Gendwnurl_BN_2147727817_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Gendwnurl.BN!bit"
        threat_id = "2147727817"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Gendwnurl"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 75 00 2e 00 6c 00 65 00 77 00 64 00 2e 00 73 00 65 00 2f 00 [0-32] 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_2 = {41 00 70 00 70 00 64 00 61 00 74 00 61 00 [0-16] 2e 00 45 00 78 00 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Gendwnurl_BR_2147728373_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Gendwnurl.BR!bit"
        threat_id = "2147728373"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Gendwnurl"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "aHR0cHM6Ly93d3cudXBsb2FkLmVlL2Rvd25sb2FkL" wide //weight: 1
        $x_1_2 = "XFNlcnZlci5leGU=" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Gendwnurl_BS_2147728374_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Gendwnurl.BS!bit"
        threat_id = "2147728374"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Gendwnurl"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 62 00 69 00 74 00 62 00 75 00 63 00 6b 00 65 00 74 00 2e 00 6f 00 72 00 67 00 2f 00 [0-37] 2f 00 64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 73 00 2f 00 [0-16] 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_2 = {43 00 3a 00 5c 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 44 00 61 00 74 00 61 00 5c 00 [0-16] 2e 00 76 00 62 00 73 00}  //weight: 1, accuracy: Low
        $x_1_3 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 35 00 2e 00 34 00 35 00 2e 00 38 00 32 00 2e 00 32 00 34 00 33 00 2f 00 [0-6] 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Gendwnurl_BT_2147728375_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Gendwnurl.BT!bit"
        threat_id = "2147728375"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Gendwnurl"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 72 00 61 00 6e 00 67 00 75 00 2e 00 75 00 63 00 6f 00 7a 00 2e 00 6e 00 65 00 74 00 2f 00 [0-6] 2e 00 72 00 61 00 72 00}  //weight: 1, accuracy: Low
        $x_1_2 = {43 00 3a 00 5c 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 44 00 61 00 74 00 61 00 [0-16] 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_3 = {43 00 3a 00 5c 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 44 00 61 00 74 00 61 00 [0-16] 2e 00 72 00 61 00 72 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Gendwnurl_CB_2147735329_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Gendwnurl.CB!bit"
        threat_id = "2147735329"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Gendwnurl"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 00 3a 00 5c 00 5f 00 78 00 66 00 61 00 63 00 65 00 [0-16] 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_2 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 77 00 6d 00 64 00 39 00 65 00 2e 00 61 00 33 00 69 00 31 00 76 00 76 00 76 00 2e 00 66 00 65 00 74 00 65 00 62 00 6f 00 63 00 2e 00 63 00 6f 00 6d 00 2f 00 78 00 73 00 6f 00 [0-16] 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_3 = "C:\\Users\\tuann\\OneDrive\\XSOFT\\XFace\\SETUP\\AutoUpdateXface\\Xface\\obj\\Debug\\AutoUpdateXface.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Gendwnurl_QQ_2147795242_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Gendwnurl.QQ!MTB"
        threat_id = "2147795242"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Gendwnurl"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {07 09 03 08 17 28 ?? 00 00 0a 28 ?? 00 00 0a 61 28 ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a 0b 00 08 17 58 b5 0c 08 11 04 13 05 11 05 31 d1}  //weight: 10, accuracy: Low
        $x_3_2 = "add_Shutdown" ascii //weight: 3
        $x_3_3 = "Downloading assets" ascii //weight: 3
        $x_3_4 = "/Isass.exe" ascii //weight: 3
        $x_3_5 = "\\Users\\MasterHy" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

