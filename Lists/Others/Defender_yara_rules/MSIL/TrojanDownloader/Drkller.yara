rule TrojanDownloader_MSIL_Drkller_A_2147730672_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Drkller.A!bit"
        threat_id = "2147730672"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Drkller"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_2 = "procexp" wide //weight: 1
        $x_1_3 = "DisableCMD" wide //weight: 1
        $x_1_4 = "\\wininit.exe" wide //weight: 1
        $x_1_5 = "http://www.whatsmyip.us/showipsimple.php" wide //weight: 1
        $x_1_6 = "smtp.gmail.com" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

