rule TrojanDownloader_Win32_Swity_C_2147679086_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Swity.C"
        threat_id = "2147679086"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Swity"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 74 70 6c 69 73 74 61 72 61 72 71 75 69 76 6f 73 00}  //weight: 1, accuracy: High
        $x_1_2 = {6c 69 71 75 69 64 61 72 74 6f 64 6f 73 6f 73 64 61 64 6f 73 69 65 63 68 72 6f 6d 65 00}  //weight: 1, accuracy: High
        $x_1_3 = {89 45 dc 8d 4d c4 51 8d 55 c8 52 6a 02 27 00 8d 4d c8 ff 15 ?? ?? ?? ?? 50 68 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 8b d0 8d 4d c4 ff 15 ?? ?? ?? ?? 50 ff 15}  //weight: 1, accuracy: Low
        $x_1_4 = {e9 03 02 00 00 8b 55 0c 8d 4e 58 8b 02 50 51 ff 15 ?? ?? ?? ?? 8b 17 68 ?? ?? ?? ?? 52 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_Win32_Swity_E_2147693741_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Swity.E"
        threat_id = "2147693741"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Swity"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ftplistararquivos" ascii //weight: 1
        $x_1_2 = "resgatarftpon" ascii //weight: 1
        $x_1_3 = "RunDll32.exe InetCpl.cpl,ClearMyTracksByProcess 1" wide //weight: 1
        $x_1_4 = "\\Dados de aplicativos\\Google\\Chrome" wide //weight: 1
        $x_1_5 = "http://goo.gl/" wide //weight: 1
        $x_1_6 = "...Intentando conectar a:" wide //weight: 1
        $x_1_7 = "[=Nome da Placa:" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

