rule TrojanSpy_MSIL_Ambsteal_A_2147688962_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Ambsteal.A"
        threat_id = "2147688962"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Ambsteal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {2d 00 4c 00 6f 00 67 00 73 00 2d 00 ?? ?? 2d 00 50 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 73 00 2d 00}  //weight: 10, accuracy: Low
        $x_10_2 = "ILAddToStartUp" ascii //weight: 10
        $x_1_3 = "\\Google\\Chrome\\User Data\\Default\\Login Data" wide //weight: 1
        $x_1_4 = "\\Apple Computer\\Preferences\\keychain.plist" wide //weight: 1
        $x_1_5 = "Password.NET Messenger Service" wide //weight: 1
        $x_1_6 = "Software\\DownloadManager\\Passwords" wide //weight: 1
        $x_1_7 = "SELECT * FROM moz_logins" wide //weight: 1
        $x_1_8 = "\\Opera\\Opera\\profile\\wand.dat" wide //weight: 1
        $x_1_9 = "Software\\IncrediMail\\Identities\\" wide //weight: 1
        $x_1_10 = "\\FTP Commander Deluxe\\FTPLIST.TXT" wide //weight: 1
        $x_1_11 = "\\FileZilla\\sitemanager.xml" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

