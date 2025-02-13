rule Rogue_MacOS_X_FakeMacdef_161701_0
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:MacOS_X/FakeMacdef"
        threat_id = "161701"
        type = "Rogue"
        platform = "MacOS_X: "
        family = "FakeMacdef"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {68 74 74 70 3a 2f 2f 25 40 2f 6d 61 63 2f 73 6f 66 74 2e 70 68 70 3f 61 66 66 69 64 3d 25 40 00}  //weight: 2, accuracy: High
        $x_2_2 = "cd /Applications;unzip %@;rm -rf __MACOSX" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Rogue_MacOS_X_FakeMacdef_161701_1
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:MacOS_X/FakeMacdef"
        threat_id = "161701"
        type = "Rogue"
        platform = "MacOS_X: "
        family = "FakeMacdef"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {68 74 74 70 3a 2f 2f 25 40 2f 6d 61 63 2e 70 68 70 25 40 00}  //weight: 2, accuracy: High
        $x_2_2 = {3f 76 3d 25 40 26 61 66 66 69 64 3d 25 40 26 64 61 74 61 3d 25 40 00}  //weight: 2, accuracy: High
        $x_2_3 = {89 54 24 04 89 04 24 e8 ?? ?? ?? ?? 83 f8 01 19 f6 83 e6 02 46 8b 83 ?? ?? ?? ?? 89 44 24 04 8b 83 ?? ?? ?? ?? 89 04 24 e8}  //weight: 2, accuracy: Low
        $x_2_4 = {8b 7d 08 0f b6 75 10 c6 87 ?? ?? 00 00 00 c7 44 24 08 00 00 80 3e 8b 83 ?? ?? ?? ?? 89 44 24 04 89 3c 24 e8}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Rogue_MacOS_X_FakeMacdef_161701_2
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:MacOS_X/FakeMacdef"
        threat_id = "161701"
        type = "Rogue"
        platform = "MacOS_X: "
        family = "FakeMacdef"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {68 74 74 70 3a 2f 2f 25 40 2f 6d 61 63 2e 70 68 70 3f 61 66 66 69 64 3d 25 40 00}  //weight: 2, accuracy: High
        $x_2_2 = {68 74 74 70 3a 2f 2f 25 40 2f 69 2e 70 68 70 3f 61 66 66 69 64 3d 25 40 00}  //weight: 2, accuracy: High
        $x_2_3 = {89 54 24 04 89 04 24 e8 ?? ?? ?? ?? 83 f8 01 19 db 83 e3 02 43 a1 ?? ?? ?? ?? 89 44 24 04 a1 ?? ?? ?? ?? 89 04 24 e8}  //weight: 2, accuracy: Low
        $x_2_4 = {8b 75 08 0f b6 5d 10 (c6 86 ?? ?? 00|c6 46 ??) c7 44 24 08 00 00 80 3e a1 ?? ?? ?? ?? 89 44 24 04 89 34 24 e8}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

