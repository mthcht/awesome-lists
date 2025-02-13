rule TrojanDownloader_O97M_Gamaredon_AA_2147742089_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Gamaredon.AA"
        threat_id = "2147742089"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Gamaredon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 22 68 74 74 70 3a 2f 2f 77 69 66 63 2e 77 65 62 73 69 74 65 2f 22 20 26 20 [0-32] 20 26 20 22 5f 22 20 26 20 48 65 78 28 [0-32] 29 20 26 20 22 2f 45 78 65 6c 43 72 65 61 74 65 5f 76 2e [0-32] 2e 73 6d 73 22}  //weight: 1, accuracy: Low
        $x_1_2 = "= Environ(\"temp\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Gamaredon_P_2147750216_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Gamaredon.P!MSR"
        threat_id = "2147750216"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Gamaredon"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "solod.bounceme.net" ascii //weight: 1
        $x_1_2 = ".RegRead(\"HKCU\\Keyboard Layout\\Preload" ascii //weight: 1
        $x_1_3 = "telemetriya.php" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

