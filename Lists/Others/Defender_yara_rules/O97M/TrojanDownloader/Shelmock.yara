rule TrojanDownloader_O97M_Shelmock_A_2147713064_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Shelmock.A!dha"
        threat_id = "2147713064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Shelmock"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Base64String(\\\"\" \" & str & \" \\\"\" )" ascii //weight: 1
        $x_1_2 = "powershell.exe" ascii //weight: 1
        $x_1_3 = "-NoP -NonI -W Hidden -Exec Bypass -Comm" ascii //weight: 1
        $x_1_4 = "exec = exec + \"ession.CompressionMode]::Decompress)), [Text.Enc\"" ascii //weight: 1
        $x_1_5 = "Shell exec, vbHide" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

