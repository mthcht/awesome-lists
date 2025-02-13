rule Worm_MSIL_Sipia_A_2147695309_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:MSIL/Sipia.A"
        threat_id = "2147695309"
        type = "Worm"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Sipia"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Folder_Spread" ascii //weight: 1
        $x_1_2 = "SpreadP2P" ascii //weight: 1
        $x_1_3 = "ShortcutSpread" ascii //weight: 1
        $x_1_4 = "startip" ascii //weight: 1
        $x_1_5 = "apexspread" ascii //weight: 1
        $x_1_6 = "lan_sp" ascii //weight: 1
        $x_1_7 = "KillNoIp" ascii //weight: 1
        $x_1_8 = "BlockAV" ascii //weight: 1
        $x_1_9 = "bsod" ascii //weight: 1
        $x_1_10 = "SpyTheSpy" ascii //weight: 1
        $x_1_11 = "FirfeWall" ascii //weight: 1
        $x_1_12 = "AStartup" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Worm_MSIL_Sipia_A_2147695309_1
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:MSIL/Sipia.A"
        threat_id = "2147695309"
        type = "Worm"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Sipia"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "[Spreadlnk]" wide //weight: 1
        $x_1_2 = "[SpreadP2P]" wide //weight: 1
        $x_1_3 = "[Kill No-IP]" wide //weight: 1
        $x_1_4 = "[BlockAVSite]" wide //weight: 1
        $x_1_5 = "[SI]" wide //weight: 1
        $x_1_6 = "[SpreadLAN]" wide //weight: 1
        $x_1_7 = "[BSOD]" wide //weight: 1
        $x_1_8 = "[SpreadFolder]" wide //weight: 1
        $x_1_9 = {5b 00 41 00 6e 00 74 00 69 00 ?? 5d 00}  //weight: 1, accuracy: Low
        $x_1_10 = "[ApexSpread]" wide //weight: 1
        $x_1_11 = "SpyTheSpy" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

