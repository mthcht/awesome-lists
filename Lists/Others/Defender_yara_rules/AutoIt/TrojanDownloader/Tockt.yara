rule TrojanDownloader_AutoIt_Tockt_A_2147711784_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:AutoIt/Tockt.A!bit"
        threat_id = "2147711784"
        type = "TrojanDownloader"
        platform = "AutoIt: AutoIT scripts"
        family = "Tockt"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "CALL ( \"podek\" )" wide //weight: 2
        $x_1_2 = "$YGXREBXBUTBVDGWREYYC = @APPDATACOMMONDIR & \"\\SysGkt\"" wide //weight: 1
        $x_1_3 = "$YGXREBXBUTBVDGWREYYC = @APPDATACOMMONDIR & \"\\SysToc\"" wide //weight: 1
        $x_2_4 = {24 00 42 00 52 00 48 00 43 00 4f 00 4c 00 47 00 45 00 46 00 46 00 42 00 5a 00 45 00 56 00 4b 00 46 00 4e 00 59 00 4c 00 4f 00 20 00 3d 00 20 00 42 00 49 00 4e 00 41 00 52 00 59 00 54 00 4f 00 53 00 54 00 52 00 49 00 4e 00 47 00 20 00 28 00 20 00 49 00 4e 00 45 00 54 00 52 00 45 00 41 00 44 00 20 00 28 00 20 00 22 00 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 [0-128] 2e 00 7a 00 69 00 70 00 22 00 20 00 29 00 20 00 2c 00 20 00 31 00 20 00 29 00}  //weight: 2, accuracy: Low
        $x_2_5 = {52 00 55 00 4e 00 20 00 28 00 20 00 24 00 59 00 47 00 58 00 52 00 45 00 42 00 58 00 42 00 55 00 54 00 42 00 56 00 44 00 47 00 57 00 52 00 45 00 59 00 59 00 43 00 20 00 26 00 20 00 22 00 5c 00 [0-16] 2e 00 65 00 78 00 65 00 22 00 20 00 29 00}  //weight: 2, accuracy: Low
        $x_2_6 = {46 00 49 00 4c 00 45 00 44 00 45 00 4c 00 45 00 54 00 45 00 20 00 28 00 20 00 24 00 59 00 47 00 58 00 52 00 45 00 42 00 58 00 42 00 55 00 54 00 42 00 56 00 44 00 47 00 57 00 52 00 45 00 59 00 59 00 43 00 20 00 26 00 20 00 22 00 5c 00 [0-16] 2e 00 7a 00 69 00 70 00 22 00 20 00 29 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

