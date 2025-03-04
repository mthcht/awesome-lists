rule Adware_AndroidOS_MobiDash_A_347602_0
{
    meta:
        author = "defender2yara"
        detection_name = "Adware:AndroidOS/MobiDash.A!MTB"
        threat_id = "347602"
        type = "Adware"
        platform = "AndroidOS: Android operating system"
        family = "MobiDash"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {60 00 98 00 6f 20 ec 09 98 00 6e 10 91 0f 08 00 52 81 dc 01 b7 91 59 89 dc 01 dd 02 09 04 12 03 12 14 39 02 04 00 12 12 28 02}  //weight: 3, accuracy: High
        $x_3_2 = "c400f128e8d03502897e8b6ac1d76950.com/" ascii //weight: 3
        $x_1_3 = {6e 65 74 2f [0-32] 4d 61 69 6e 41 63 74 69 76 69 74 79 24 61}  //weight: 1, accuracy: Low
        $x_1_4 = "PreloadInfo" ascii //weight: 1
        $x_1_5 = "Lockscreen" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_3_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Adware_AndroidOS_MobiDash_D_347930_0
{
    meta:
        author = "defender2yara"
        detection_name = "Adware:AndroidOS/MobiDash.D!MTB"
        threat_id = "347930"
        type = "Adware"
        platform = "AndroidOS: Android operating system"
        family = "MobiDash"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {60 00 98 00 6f 20 ec 09 98 00 6e 10 91 0f 08 00 52 81 dc 01 b7 91 59 89 dc 01 dd 02 09 04 12 03 12 14 39 02 04 00 12 12 28 02}  //weight: 1, accuracy: High
        $x_1_2 = "b97b56c8dbaf709c240bcaa026fa47aa.com" ascii //weight: 1
        $x_1_3 = "hide_app_icon" ascii //weight: 1
        $x_1_4 = "$this$getinstalldate" ascii //weight: 1
        $x_1_5 = "EndlessService::lock" ascii //weight: 1
        $x_1_6 = "SSReceiverProxy" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Adware_AndroidOS_MobiDash_E_349053_0
{
    meta:
        author = "defender2yara"
        detection_name = "Adware:AndroidOS/MobiDash.E!MTB"
        threat_id = "349053"
        type = "Adware"
        platform = "AndroidOS: Android operating system"
        family = "MobiDash"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com/luskacrewmods/amongmods" ascii //weight: 1
        $x_1_2 = "/system/app/Superuser.apk" ascii //weight: 1
        $x_1_3 = "MobileAds" ascii //weight: 1
        $x_1_4 = "InterstitialAd" ascii //weight: 1
        $x_3_5 = "propublica.db" ascii //weight: 3
        $x_3_6 = "spice7.db" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 3 of ($x_1_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Adware_AndroidOS_MobiDash_G_349919_0
{
    meta:
        author = "defender2yara"
        detection_name = "Adware:AndroidOS/MobiDash.G!MTB"
        threat_id = "349919"
        type = "Adware"
        platform = "AndroidOS: Android operating system"
        family = "MobiDash"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {38 03 57 00 22 01 0e 08 1a 04 ?? 4b 70 30 ?? ?? 71 04 12 14 6e 20 ?? ?? 41 00 0c 04 12 35}  //weight: 1, accuracy: Low
        $x_1_2 = {22 01 89 08 70 10 ?? ?? 01 00 6e 10 ?? ?? 01 00 0c 00 54 21 54 1b 6e 20 ?? ?? 01 00}  //weight: 1, accuracy: Low
        $x_1_3 = {0a 00 38 00 08 00 54 a0 53 1b 6e 10 ?? ?? 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Adware_AndroidOS_MobiDash_H_350293_0
{
    meta:
        author = "defender2yara"
        detection_name = "Adware:AndroidOS/MobiDash.H!MTB"
        threat_id = "350293"
        type = "Adware"
        platform = "AndroidOS: Android operating system"
        family = "MobiDash"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "com/tmflabs/swimmingtutorial/MainActivity" ascii //weight: 2
        $x_2_2 = "om/ossibussoftware/deadpixeltest/Provider" ascii //weight: 2
        $x_1_3 = "MobileAds" ascii //weight: 1
        $x_1_4 = "InterstitialAd" ascii //weight: 1
        $x_1_5 = "deadpixeltest.db" ascii //weight: 1
        $x_1_6 = "DexClassLoader" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Adware_AndroidOS_MobiDash_B_350720_0
{
    meta:
        author = "defender2yara"
        detection_name = "Adware:AndroidOS/MobiDash.B!MTB"
        threat_id = "350720"
        type = "Adware"
        platform = "AndroidOS: Android operating system"
        family = "MobiDash"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {70 10 bb d6 01 00 12 00 5b 10 ?? ?? 12 00 5c 10 ?? ?? 0e 00 06 00 02 00 04 00 03 00 ?? ?? 4a 00 46 00 00 00 22 00 ?? ?? 12 01 70 30}  //weight: 1, accuracy: Low
        $x_1_2 = {63 6f 6d 2f 6d 63 73 6b 69 6e 32 31 2f 44 72 65 61 6d 2f [0-32] 6f 6e 43 72 65 61 74 65}  //weight: 1, accuracy: Low
        $x_1_3 = "com/mcskin21/Dream/SplashActivity" ascii //weight: 1
        $x_1_4 = "setAdListener" ascii //weight: 1
        $x_1_5 = "mInterstitialAd" ascii //weight: 1
        $x_1_6 = "DexClassLoader" ascii //weight: 1
        $x_1_7 = "MobileAds.initialize" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Adware_AndroidOS_MobiDash_C_350721_0
{
    meta:
        author = "defender2yara"
        detection_name = "Adware:AndroidOS/MobiDash.C!MTB"
        threat_id = "350721"
        type = "Adware"
        platform = "AndroidOS: Android operating system"
        family = "MobiDash"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {38 02 1c 00 71 00 ?? ?? 00 00 71 00 ?? ?? 00 00 12 02 67 02 ?? ?? 22 02 93 00 1c 03 ?? ?? 70 30 16 03 42 03 6e 20 ?? ?? 24 00 6e 10 ?? ?? 04 00 71 00 ?? ?? 00 00 0e 00 22 01 95 07}  //weight: 1, accuracy: Low
        $x_1_2 = "com/nupuit/pmp1/activity" ascii //weight: 1
        $x_1_3 = "MobileAds" ascii //weight: 1
        $x_1_4 = "5930eda8cfa5ab3908001540" ascii //weight: 1
        $x_1_5 = "mInterstitialAd" ascii //weight: 1
        $x_1_6 = "DexClassLoader" ascii //weight: 1
        $x_1_7 = {63 6f 6d 2f 6e 75 70 75 69 74 2f [0-32] 61 63 74 69 76 69 74 79 2f 4d 6f 63 6b 75 70 41 63 74 69 76 69 74 79}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Adware_AndroidOS_MobiDash_F_350722_0
{
    meta:
        author = "defender2yara"
        detection_name = "Adware:AndroidOS/MobiDash.F!MTB"
        threat_id = "350722"
        type = "Adware"
        platform = "AndroidOS: Android operating system"
        family = "MobiDash"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com/firestream/titanconquest" ascii //weight: 1
        $x_1_2 = "/system/app/Superuser.apk" ascii //weight: 1
        $x_1_3 = "mobileads" ascii //weight: 1
        $x_1_4 = "InterstitialAd" ascii //weight: 1
        $x_1_5 = "DexClassLoader" ascii //weight: 1
        $x_1_6 = "titanconquest.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Adware_AndroidOS_MobiDash_K_351899_0
{
    meta:
        author = "defender2yara"
        detection_name = "Adware:AndroidOS/MobiDash.K!MTB"
        threat_id = "351899"
        type = "Adware"
        platform = "AndroidOS: Android operating system"
        family = "MobiDash"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sonidosparadormir.db" ascii //weight: 1
        $x_1_2 = "mobileads" ascii //weight: 1
        $x_1_3 = "InterstitialAd" ascii //weight: 1
        $x_1_4 = "DexClassLoader" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Adware_AndroidOS_MobiDash_L_351900_0
{
    meta:
        author = "defender2yara"
        detection_name = "Adware:AndroidOS/MobiDash.L!MTB"
        threat_id = "351900"
        type = "Adware"
        platform = "AndroidOS: Android operating system"
        family = "MobiDash"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com/ffs/superheroes/junior/Provider" ascii //weight: 1
        $x_1_2 = "junior.db" ascii //weight: 1
        $x_1_3 = "mkdirChecked" ascii //weight: 1
        $x_1_4 = "DexClassLoader" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Adware_AndroidOS_MobiDash_M_351901_0
{
    meta:
        author = "defender2yara"
        detection_name = "Adware:AndroidOS/MobiDash.M!MTB"
        threat_id = "351901"
        type = "Adware"
        platform = "AndroidOS: Android operating system"
        family = "MobiDash"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "com/amosmobile/rootcheck/RootCheckActivity" ascii //weight: 1
        $x_1_2 = "shareMyData" ascii //weight: 1
        $x_1_3 = {6d 61 69 6c 74 6f ?? 61 6d 6f 73 6d 6f 62 69 6c 65 35 35 40 67 6d 61 69 6c 2e 63 6f 6d}  //weight: 1, accuracy: Low
        $x_1_4 = "NotificationListener" ascii //weight: 1
        $x_1_5 = "DexClassLoader" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Adware_AndroidOS_MobiDash_O_353094_0
{
    meta:
        author = "defender2yara"
        detection_name = "Adware:AndroidOS/MobiDash.O!MTB"
        threat_id = "353094"
        type = "Adware"
        platform = "AndroidOS: Android operating system"
        family = "MobiDash"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "app794734.db" ascii //weight: 1
        $x_1_2 = "com/allahwallpaper/hdwallpaper/allah/islamic/kaligrafi/app794734" ascii //weight: 1
        $x_1_3 = "MobileAds" ascii //weight: 1
        $x_1_4 = "InterstitialAd" ascii //weight: 1
        $x_1_5 = "DexClassLoader" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Adware_AndroidOS_MobiDash_P_354217_0
{
    meta:
        author = "defender2yara"
        detection_name = "Adware:AndroidOS/MobiDash.P!MTB"
        threat_id = "354217"
        type = "Adware"
        platform = "AndroidOS: Android operating system"
        family = "MobiDash"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "org/cocos2dx/jamms/hohoho/Provider" ascii //weight: 1
        $x_1_2 = "hohoho.db" ascii //weight: 1
        $x_1_3 = "DexClassLoader" ascii //weight: 1
        $x_1_4 = "NotificationListener" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Adware_AndroidOS_MobiDash_Q_354218_0
{
    meta:
        author = "defender2yara"
        detection_name = "Adware:AndroidOS/MobiDash.Q!MTB"
        threat_id = "354218"
        type = "Adware"
        platform = "AndroidOS: Android operating system"
        family = "MobiDash"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com/daramedia/perfumeoil/Provider" ascii //weight: 1
        $x_1_2 = "perfumeoil.db" ascii //weight: 1
        $x_1_3 = "DexClassLoader" ascii //weight: 1
        $x_1_4 = "NotificationListener" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Adware_AndroidOS_MobiDash_R_354812_0
{
    meta:
        author = "defender2yara"
        detection_name = "Adware:AndroidOS/MobiDash.R!MTB"
        threat_id = "354812"
        type = "Adware"
        platform = "AndroidOS: Android operating system"
        family = "MobiDash"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com/saint/francislp/Provider" ascii //weight: 1
        $x_1_2 = "francislp.db" ascii //weight: 1
        $x_1_3 = "DexClassLoader" ascii //weight: 1
        $x_1_4 = "francislp.dat.jar" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Adware_AndroidOS_MobiDash_S_354813_0
{
    meta:
        author = "defender2yara"
        detection_name = "Adware:AndroidOS/MobiDash.S!MTB"
        threat_id = "354813"
        type = "Adware"
        platform = "AndroidOS: Android operating system"
        family = "MobiDash"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com/cyrosehdmovie/boxoffice/Provider" ascii //weight: 1
        $x_1_2 = "boxoffice.db" ascii //weight: 1
        $x_1_3 = "DexClassLoader" ascii //weight: 1
        $x_1_4 = "NotificationListener" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Adware_AndroidOS_MobiDash_T_354814_0
{
    meta:
        author = "defender2yara"
        detection_name = "Adware:AndroidOS/MobiDash.T!MTB"
        threat_id = "354814"
        type = "Adware"
        platform = "AndroidOS: Android operating system"
        family = "MobiDash"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {04 00 0c 01 6e 10 ?? ?? 01 00 0c 02 6e 10 ?? ?? 01 00 0c 01 6e 10 ?? ?? 04 00 0c 04 6e 10 ?? ?? 02 00 6e 20 ?? ?? 04 00 0c 04 22 00 ?? ?? ?? ?? ?? ?? 10 00 70 30 ?? ?? 43 00 28 05 0d 04}  //weight: 1, accuracy: Low
        $x_1_2 = "ancientrome.db" ascii //weight: 1
        $x_1_3 = "DexClassLoader" ascii //weight: 1
        $x_1_4 = "NotificationListener" ascii //weight: 1
        $x_1_5 = "InterstitialAd" ascii //weight: 1
        $x_1_6 = "MobileAds" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Adware_AndroidOS_MobiDash_U_356951_0
{
    meta:
        author = "defender2yara"
        detection_name = "Adware:AndroidOS/MobiDash.U!MTB"
        threat_id = "356951"
        type = "Adware"
        platform = "AndroidOS: Android operating system"
        family = "MobiDash"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cardview.db" ascii //weight: 1
        $x_1_2 = "MobileAds" ascii //weight: 1
        $x_1_3 = "ide/creator/ngabean/cardview" ascii //weight: 1
        $x_1_4 = "DexClassLoader" ascii //weight: 1
        $x_1_5 = "InterstitialAd" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Adware_AndroidOS_MobiDash_U_356951_1
{
    meta:
        author = "defender2yara"
        detection_name = "Adware:AndroidOS/MobiDash.U!MTB"
        threat_id = "356951"
        type = "Adware"
        platform = "AndroidOS: Android operating system"
        family = "MobiDash"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com/talking/noel/Provider" ascii //weight: 1
        $x_1_2 = "noel.db" ascii //weight: 1
        $x_1_3 = "DexClassLoader" ascii //weight: 1
        $x_1_4 = "NotificationListener" ascii //weight: 1
        $x_1_5 = "InterstitialAd" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Adware_AndroidOS_MobiDash_V_357286_0
{
    meta:
        author = "defender2yara"
        detection_name = "Adware:AndroidOS/MobiDash.V!MTB"
        threat_id = "357286"
        type = "Adware"
        platform = "AndroidOS: Android operating system"
        family = "MobiDash"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com/thorapps/inchestocentimeters/Provider" ascii //weight: 1
        $x_1_2 = "DexClassLoader" ascii //weight: 1
        $x_1_3 = "inchestocentimeters.db" ascii //weight: 1
        $x_1_4 = "MobileAds" ascii //weight: 1
        $x_1_5 = "NotificationListener" ascii //weight: 1
        $x_1_6 = "OnAppInstallAdLoadedListener" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Adware_AndroidOS_MobiDash_Y_360146_0
{
    meta:
        author = "defender2yara"
        detection_name = "Adware:AndroidOS/MobiDash.Y!MTB"
        threat_id = "360146"
        type = "Adware"
        platform = "AndroidOS: Android operating system"
        family = "MobiDash"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com/priorityhealth/memberportal" ascii //weight: 1
        $x_1_2 = "memberportal.db" ascii //weight: 1
        $x_1_3 = "getClassLoader" ascii //weight: 1
        $x_1_4 = "loadLibs" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Adware_AndroidOS_MobiDash_Z_360147_0
{
    meta:
        author = "defender2yara"
        detection_name = "Adware:AndroidOS/MobiDash.Z!MTB"
        threat_id = "360147"
        type = "Adware"
        platform = "AndroidOS: Android operating system"
        family = "MobiDash"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Lcom/kacyano/megasena" ascii //weight: 1
        $x_1_2 = "Lcom/bubblingiso/dmvchinese" ascii //weight: 1
        $x_1_3 = "dmvchinese.db" ascii //weight: 1
        $x_1_4 = "DexClassLoader" ascii //weight: 1
        $x_1_5 = "sendNotification" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Adware_AndroidOS_MobiDash_AA_360675_0
{
    meta:
        author = "defender2yara"
        detection_name = "Adware:AndroidOS/MobiDash.AA!MTB"
        threat_id = "360675"
        type = "Adware"
        platform = "AndroidOS: Android operating system"
        family = "MobiDash"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {30 4a 30 4b 20 1c 31 1c 7a 44 7b 44 ff f7 07 fd 04 90 20 1c ff f7 2c fd 00 28 d6 d1 2b 4a 2b 4b 20 1c 31 1c 7a 44 7b 44 ff f7 f9 fc 05 90 20 1c ff f7 1e fd 00 28}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Adware_AndroidOS_MobiDash_AD_433492_0
{
    meta:
        author = "defender2yara"
        detection_name = "Adware:AndroidOS/MobiDash.AD!MTB"
        threat_id = "433492"
        type = "Adware"
        platform = "AndroidOS: Android operating system"
        family = "MobiDash"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com/propublica" ascii //weight: 1
        $x_1_2 = "propublica.db" ascii //weight: 1
        $x_1_3 = "InterstitialAd" ascii //weight: 1
        $x_1_4 = "NotificationListener" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

