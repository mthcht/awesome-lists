rule TrojanDownloader_O97M_Ocilo_A_2147735912_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Ocilo.A"
        threat_id = "2147735912"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Ocilo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {45 6e 76 69 72 6f 6e 28 22 54 45 4d 50 22 29 20 26 20 22 5c ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2e 62 61 74 22}  //weight: 1, accuracy: Low
        $x_1_2 = "fCheck.FileExists(\"C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\MSBuild.exe\")" ascii //weight: 1
        $x_1_3 = {43 61 6c 6c 20 53 68 65 6c 6c 28 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2c 20 76 62 48 69 64 65 29}  //weight: 1, accuracy: Low
        $x_1_4 = {45 6e 76 69 72 6f 6e 28 22 54 45 4d 50 22 29 20 26 20 22 5c ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2e 74 78 74 22}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

