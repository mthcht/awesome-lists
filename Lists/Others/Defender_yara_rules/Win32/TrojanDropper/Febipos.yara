rule TrojanDropper_Win32_Febipos_I_2147693442_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Febipos.I"
        threat_id = "2147693442"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Febipos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {3c 09 75 e7 0f b6 03 3c 20 75 73 83 c3 01 0f b6 03 3c 09 74 f6 3c 20 74 f2 f6 45 d0 01 be 0a 00 00 00 74 04 0f b7 75 d4 c7 04 24 00 00 00 00 e8 ?? ?? ?? ?? 83 ec 04 89 74 24 0c 89 5c 24 08 c7 44 24 04 00 00 00 00 89 04 24 e8}  //weight: 5, accuracy: Low
        $x_5_2 = "ytnews.info/showcountry.php" ascii //weight: 5
        $x_1_3 = "whos.amung.us/widget/okinstallbra.pnh" ascii //weight: 1
        $x_1_4 = "\"install_time\": \"13054785921145812\"" ascii //weight: 1
        $x_1_5 = {25 73 5c 74 65 6d 70 31 00 25 73 5c 74 65 6d 70 32 00}  //weight: 1, accuracy: High
        $x_1_6 = "\"name\": \"Home Cinema\"" ascii //weight: 1
        $x_1_7 = "ageaglbhlmcjipojelficnnmfmcnjeoo" ascii //weight: 1
        $x_1_8 = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQ" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

