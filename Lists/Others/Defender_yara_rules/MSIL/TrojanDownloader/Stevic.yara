rule TrojanDownloader_MSIL_Stevic_A_2147728272_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Stevic.A!bit"
        threat_id = "2147728272"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stevic"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 73 00 63 00 72 00 65 00 65 00 6e 00 68 00 6f 00 73 00 74 00 2e 00 70 00 77 00 2f 00 [0-48] 2e 00 6a 00 70 00 67 00}  //weight: 1, accuracy: Low
        $x_1_2 = "screenhost.pw/ip2.php?ex=" wide //weight: 1
        $x_1_3 = "SteamService" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

