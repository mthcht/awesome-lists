rule Adware_AndroidOS_Mobidash_I_349633_0
{
    meta:
        author = "defender2yara"
        detection_name = "Adware:AndroidOS/Mobidash.I!MTB"
        threat_id = "349633"
        type = "Adware"
        platform = "AndroidOS: Android operating system"
        family = "Mobidash"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "spellingbughangmanlite.db" ascii //weight: 2
        $x_2_2 = "maxhealthcare.db" ascii //weight: 2
        $x_1_3 = "com/realtest/namemeter/lovecalculator/activities" ascii //weight: 1
        $x_1_4 = "rkadhish/alter" ascii //weight: 1
        $x_1_5 = "dramainfotech.com/api/milestone/word.php" ascii //weight: 1
        $x_1_6 = "InterstitialAd" ascii //weight: 1
        $x_1_7 = "DexClassLoader" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((2 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Adware_AndroidOS_Mobidash_I_349633_1
{
    meta:
        author = "defender2yara"
        detection_name = "Adware:AndroidOS/Mobidash.I!MTB"
        threat_id = "349633"
        type = "Adware"
        platform = "AndroidOS: Android operating system"
        family = "Mobidash"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "com/sia/rms" ascii //weight: 1
        $x_1_2 = "com/Kayal/SwipyGoal" ascii //weight: 1
        $x_1_3 = "org/cocos2dx/cpp" ascii //weight: 1
        $x_1_4 = "/sbC9q7" ascii //weight: 1
        $x_10_5 = {13 00 00 10 23 01 ?? ?? 12 02 6e 40 ?? ?? 15 02 0a 03 3d 03 06 00 6e 40 ?? ?? 16 32 28 f6 0e 00}  //weight: 10, accuracy: Low
        $x_10_6 = {5e 00 00 00 54 40 ?? ?? 39 00 5b 00 71 10 ?? ?? 05 00 1a 00 ?? ?? 6e 20 ?? ?? 05 00 0c 01 6e 10 ?? ?? 01 00 0c 02 6e 10 ?? ?? 05 00 0c 05 6e 10 ?? ?? 01 00 0c 03 38 03 13 00 6e 10 ?? ?? 01 00 0c 03 6e 10 ?? ?? 03 00 0a 03 39 03 09 00 6e 10 ?? ?? 01 00 0c 01 6e 10 ?? ?? 01 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Adware_AndroidOS_Mobidash_J_349996_0
{
    meta:
        author = "defender2yara"
        detection_name = "Adware:AndroidOS/Mobidash.J!MTB"
        threat_id = "349996"
        type = "Adware"
        platform = "AndroidOS: Android operating system"
        family = "Mobidash"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "com/idlelawfirm/empiretycoongame" ascii //weight: 10
        $x_10_2 = "vija/summer/beach/launcher" ascii //weight: 10
        $x_10_3 = "zexica/app/summer/wallpapers" ascii //weight: 10
        $x_10_4 = "/expo/progressyourself/" ascii //weight: 10
        $x_1_5 = "onUpgrade" ascii //weight: 1
        $x_1_6 = "getPackageInfo" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Adware_AndroidOS_Mobidash_N_351976_0
{
    meta:
        author = "defender2yara"
        detection_name = "Adware:AndroidOS/Mobidash.N!MTB"
        threat_id = "351976"
        type = "Adware"
        platform = "AndroidOS: Android operating system"
        family = "Mobidash"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {39 00 3d 00 71 10 ?? ?? 03 00 1a 00 ?? ?? 6e 20 ?? ?? 03 00 0c 01 6e 10 ?? ?? 01 00 6e 10 ?? ?? 01 00 0c 01 6e 10 ?? ?? 03 00 0c 03 6e 20 ?? ?? 03 00 0c 03 22 00 ?? ?? 70 20 ?? ?? 10 00 70 30 ?? ?? 32 00 28 05}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Adware_AndroidOS_Mobidash_W_357923_0
{
    meta:
        author = "defender2yara"
        detection_name = "Adware:AndroidOS/Mobidash.W!MTB"
        threat_id = "357923"
        type = "Adware"
        platform = "AndroidOS: Android operating system"
        family = "Mobidash"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {13 00 00 10 23 01 ?? ?? 12 02 6e 40 ?? ?? 15 02 0a 03 3d 03 06 00 6e 40 ?? ?? 16 32 28 f6 0e 00}  //weight: 1, accuracy: Low
        $x_1_2 = "InterstitialAd" ascii //weight: 1
        $x_1_3 = "MobileAds" ascii //weight: 1
        $x_1_4 = "pinfo" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Adware_AndroidOS_Mobidash_AE_443018_0
{
    meta:
        author = "defender2yara"
        detection_name = "Adware:AndroidOS/Mobidash.AE!MTB"
        threat_id = "443018"
        type = "Adware"
        platform = "AndroidOS: Android operating system"
        family = "Mobidash"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com/AppyTech/appytech/MainActivity" ascii //weight: 1
        $x_1_2 = "DEMANDE_STORAGE_TO_DATA" ascii //weight: 1
        $x_1_3 = "NOM_LISTE_GRID_COPY" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Adware_AndroidOS_Mobidash_AF_456843_0
{
    meta:
        author = "defender2yara"
        detection_name = "Adware:AndroidOS/Mobidash.AF!MTB"
        threat_id = "456843"
        type = "Adware"
        platform = "AndroidOS: Android operating system"
        family = "Mobidash"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "com/mobappsbaker/uaeoffers" ascii //weight: 1
        $x_1_2 = {6e 10 b4 01 01 00 62 01 ?? 24 6e 10 b4 01 01 00 22 01 c4 00 54 02}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Adware_AndroidOS_Mobidash_AG_456844_0
{
    meta:
        author = "defender2yara"
        detection_name = "Adware:AndroidOS/Mobidash.AG!MTB"
        threat_id = "456844"
        type = "Adware"
        platform = "AndroidOS: Android operating system"
        family = "Mobidash"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {65 00 14 06 1c 00 0d 7f 6e 20 ?? 11 65 00 6e 10 ?? 15 05 00 0c 06 5b 56}  //weight: 1, accuracy: Low
        $x_1_2 = {96 14 06 b8 00 0a 7f 6e 20 ?? 11 65 00 0c 06 5b 56 ?? 96 14 06 9d 02 0a 7f 6e 20}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Adware_AndroidOS_Mobidash_AH_456845_0
{
    meta:
        author = "defender2yara"
        detection_name = "Adware:AndroidOS/Mobidash.AH!MTB"
        threat_id = "456845"
        type = "Adware"
        platform = "AndroidOS: Android operating system"
        family = "Mobidash"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "distinction/cflow/activitites" ascii //weight: 1
        $x_1_2 = "CocktailBooksActivity" ascii //weight: 1
        $x_1_3 = "/pages/glossary_notes_widget" ascii //weight: 1
        $x_1_4 = {74 00 00 0a 01 38 01 37 00 72 10 ?? 74 00 00 0c 01 1f 01 de 11 6e 10}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Adware_AndroidOS_Mobidash_AI_456846_0
{
    meta:
        author = "defender2yara"
        detection_name = "Adware:AndroidOS/Mobidash.AI!MTB"
        threat_id = "456846"
        type = "Adware"
        platform = "AndroidOS: Android operating system"
        family = "Mobidash"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 54 00 0c 04 21 45 01 26 35 56 11 00 46 07 04 06 6e 10 ?? 43 07 00 1a 08}  //weight: 1, accuracy: Low
        $x_1_2 = {12 00 6e 20 50 01 03 00 0c 00 1a 01 ?? 7e 1a 02 00 00 72 30 73 03 10 02 0c 00 1a 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Adware_AndroidOS_Mobidash_AJ_456847_0
{
    meta:
        author = "defender2yara"
        detection_name = "Adware:AndroidOS/Mobidash.AJ!MTB"
        threat_id = "456847"
        type = "Adware"
        platform = "AndroidOS: Android operating system"
        family = "Mobidash"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "com/dextrade/android/MainActivity" ascii //weight: 1
        $x_1_2 = {32 04 00 6e 10 ?? 3d 04 00 0c 00 72 10 ?? 55 00 00 0c 00 54 41 ?? 21 38 01 0c 00 22 02 19 00 12 03 70 30 62 00 42 03 6e 30 ?? 9f 10 02 0e 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Adware_AndroidOS_Mobidash_AK_456848_0
{
    meta:
        author = "defender2yara"
        detection_name = "Adware:AndroidOS/Mobidash.AK!MTB"
        threat_id = "456848"
        type = "Adware"
        platform = "AndroidOS: Android operating system"
        family = "Mobidash"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "com/expressexpense/bluetooth/print/Main_Activity" ascii //weight: 1
        $x_1_2 = {5d 01 00 54 30 ?? 48 14 01 0c 00 01 7f 14 02 0d 00 01 7f 6e 30 ?? 5d 10 02 54 30}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

