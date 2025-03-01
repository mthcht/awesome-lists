rule Backdoor_MacOS_X_FlashBack_2147650488_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MacOS_X/FlashBack"
        threat_id = "2147650488"
        type = "Backdoor"
        platform = "MacOS_X: "
        family = "FlashBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "{BSRQ}" ascii //weight: 1
        $x_1_2 = ".google." ascii //weight: 1
        $x_1_3 = "hw.machine" ascii //weight: 1
        $x_1_4 = "kern.osrelease" ascii //weight: 1
        $x_3_5 = "/Library/Preferences/Preferences.dylib" ascii //weight: 3
        $x_3_6 = {c1 ea 02 b8 15 02 4d 21 f7 e2 c1 ea 04 8b 45 0c 89 10 eb 07}  //weight: 3, accuracy: High
        $x_3_7 = {8b 55 d4 80 3a 7b 0f 84 15 02 00 00 8b 72 f4 8b 42 fc 85 c0 78 0b 89 3c 24}  //weight: 3, accuracy: High
        $x_3_8 = {49 ff c4 48 8b 43 10 48 2b 43 08 48 c1 f8 03 48 ba ab aa aa aa}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 3 of ($x_1_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

