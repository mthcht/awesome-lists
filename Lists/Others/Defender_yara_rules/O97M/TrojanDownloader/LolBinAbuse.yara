rule TrojanDownloader_O97M_LolBinAbuse_2147741794_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/LolBinAbuse!ibt"
        threat_id = "2147741794"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "LolBinAbuse"
        severity = "Critical"
        info = "ibt: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "mshta.exe javascript:getobject" ascii //weight: 1
        $x_1_2 = "Register-Cimprovider.exe -path c:" ascii //weight: 1
        $x_1_3 = "forfiles /p" ascii //weight: 1
        $x_1_4 = "C:\\Windows /m notepad.exe /c" ascii //weight: 1
        $x_1_5 = "C:\\Windows\\System32\\cmd.exe /c replace.exe " ascii //weight: 1
        $x_1_6 = "System32\\replace.exe" ascii //weight: 1
        $x_1_7 = "cmd.exe /c certutil.exe -urlcache -split -f" ascii //weight: 1
        $x_1_8 = "msiexec.exe /q /i" ascii //weight: 1
        $x_1_9 = "C:\\Windows\\System32\\Register-CimProvider.exe -path" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

