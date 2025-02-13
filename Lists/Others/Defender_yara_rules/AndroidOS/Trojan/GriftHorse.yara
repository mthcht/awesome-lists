rule Trojan_AndroidOS_GriftHorse_E_2147813701_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/GriftHorse.E!MTB"
        threat_id = "2147813701"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "GriftHorse"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "dukj0t5q4ce1u.cloudfront.net" ascii //weight: 1
        $x_1_2 = "com/vidx/videosquex/activities" ascii //weight: 1
        $x_1_3 = "getIsPremium" ascii //weight: 1
        $x_1_4 = "Rv_Clicklisterner" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_GriftHorse_F_2147813702_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/GriftHorse.F!MTB"
        threat_id = "2147813702"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "GriftHorse"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {38 03 25 00 1a 00 ?? ?? 6e 20 ?? ?? 03 00 0a 01 1a 02 ?? ?? 38 01 06 00 6e 30 ?? ?? 03 02 0c 03 6e 20 ?? ?? 23 00 0a 00 39 00 11 00 22 00 ?? ?? 70 10 ?? ?? 00 00 6e 20 ?? ?? 20 00 6e 20 ?? ?? 30 00 6e 10 ?? ?? 00 00 0c 03 71 00 ?? ?? 00 00 0c 00 22 01 ?? ?? 70 10 ?? ?? 01 00 6e 20 ?? ?? 31 00 1a 03 ?? ?? 6e 20 ?? ?? 31 00 6e 20 ?? ?? 01 00 1a 03 ?? ?? 6e 20 ?? ?? 31 00 71 00 ?? ?? 00 00 0c 03 6e 20 ?? ?? 31 00 6e 10 ?? ?? 01 00 0c 03}  //weight: 1, accuracy: Low
        $x_1_2 = "com/generalflow/bridge" ascii //weight: 1
        $x_1_3 = "ConstructURL" ascii //weight: 1
        $x_1_4 = "portalURL" ascii //weight: 1
        $x_1_5 = "withFCMNotification" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_GriftHorse_G_2147813703_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/GriftHorse.G!MTB"
        threat_id = "2147813703"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "GriftHorse"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {32 00 14 03 ?? ?? 0c 7f 6e 20 ?? ?? 32 00 14 03 ?? ?? 09 7f 6e 20 ?? ?? 32 00 0c 03 1f 03 ?? ?? 5b 23 ?? ?? 6e 10 ?? ?? 03 00 0c 03 12 10 6e 20 2e 15 03 00 54 23 ?? ?? 22 00 ?? ?? 70 10 ?? ?? 00 00 6e 20 ?? ?? 03 00 54 23 ?? ?? 22 00 ?? ?? 70 20 ?? ?? 20 00 6e 20 ?? ?? 03 00 54 23 ?? ?? 22 00 ?? ?? 70 20 ?? ?? 20 00 6e 20 ?? ?? 03 00 6e 10 ?? ?? 02 00 0c 03 54 20 ?? ?? 71 20 ?? ?? 03 00 54 23 ?? ?? 22 00 ?? ?? 70 10 ?? ?? 00 00 1a 01 ?? ?? 6e 20 ?? ?? 10 00 71 10 ?? ?? 02 00 0c 01 6e 20 ?? ?? 10 00 6e 10 ?? ?? 00 00 0c 00 6e 20 ?? ?? 03 00}  //weight: 10, accuracy: Low
        $x_10_2 = {0c 00 12 11 6e 20 ?? ?? 10 00 54 30 ?? ?? 6e 10 ?? ?? 00 00 0c 00 6e 20 ?? ?? 10 00 54 30 ?? ?? 22 01 ?? ?? 70 10 ?? ?? 01 00 6e 20 ?? ?? 10 00 54 30 ?? ?? 22 01 ?? ?? 70 20 ?? ?? 31 00 6e 20 ?? ?? 10 00 6e 10 ?? ?? 03 00 0c 00 54 31 ?? ?? 71 20 ?? ?? 10 00 54 30 ?? ?? 22 01 ?? ?? 70 10 ?? ?? 01 00 1a 02 ?? ?? 6e 20 ?? ?? 21 00 54 32 ?? ?? 71 10 ?? ?? 02 00 0c 02 6e 20 ?? ?? 21 00 6e 10 ?? ?? 01 00 0c 01 6e 20 ?? ?? 10 00}  //weight: 10, accuracy: Low
        $x_5_3 = {70 73 3a 2f 2f 64 [0-32] 2e 63 6c 6f 75 64 66 72 6f 6e 74 2e 6e 65 74 2f 63 6f 6d 2e [0-53] 2e 68 74 6d 6c 3f}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_5_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_AndroidOS_GriftHorse_H_2147814105_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/GriftHorse.H!MTB"
        threat_id = "2147814105"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "GriftHorse"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0c 04 1f 04 ?? ?? 6e 10 ?? ?? 04 00 0c 00 12 01 71 10 ?? ?? 01 00 0c 02 38 00 20 00 6e 10 ?? ?? 04 00 0c 04 6e 10 ?? ?? 04 00 0a 04 38 04 16 00 1a 04 ?? ?? 71 10 ?? ?? 04 00 0c 04 1a 00 00 00 6e 20 ?? ?? 04 00 0a 04 39 04 03 00 12 11 71 10 ?? ?? 01 00 0c 04 11 04}  //weight: 1, accuracy: Low
        $x_1_2 = "Activity$Checknet" ascii //weight: 1
        $x_1_3 = {68 74 74 70 73 3a 2f 2f 64 [0-32] 2e 63 6c 6f 75 64 66 72 6f 6e 74 2e 6e 65 74 2f 63 6f 6d 2e [0-80] 2e 68 74 6d 6c 3f}  //weight: 1, accuracy: Low
        $x_1_4 = "getDeviceIdFromDevice" ascii //weight: 1
        $x_1_5 = {01 00 0c 01 1a 00 ?? ?? 71 20 ?? ?? 01 00 0c 01 38 01 09 00 6e 10 ?? ?? 01 00 0a 00 39 00 03 00 11 01 39 01 04 00 1a 01 00 00 11 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_GriftHorse_I_2147814199_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/GriftHorse.I!MTB"
        threat_id = "2147814199"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "GriftHorse"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {32 00 14 03 ?? ?? ?? 7f 6e 20 ?? ?? 32 00 [0-8] 14 03 ?? ?? ?? 7f 6e 20 ?? ?? 32 00 0c 03 1f 03 ?? ?? 5b 23 [0-8] 6e 10 ?? ?? 03 00 0c 03 12 10 6e 20 ?? ?? 03 00 54 23 ?? ?? 22 00 ?? ?? 70 10 ?? ?? 00 00 6e 20 ?? ?? 03 00 54 23 ?? ?? 22 00 ?? ?? 70 20 ?? ?? 20 00 6e 20 ?? ?? 03 00 [0-37] 6e 10 ?? ?? 02 00 0c 03 54 20 ?? ?? 71 20 ?? ?? 03 00 54 23 ?? ?? 22 00 ?? ?? 70 10 ?? ?? 00 00 1a 01 ?? ?? 6e 20 ?? ?? 10 00 [0-8] 71 10 ?? ?? ?? 00 0c 01 6e 20 ?? ?? 10 00 6e 10 ?? ?? 00 00 0c 00 6e 20 ?? ?? 03 00}  //weight: 10, accuracy: Low
        $x_10_2 = {12 10 6e 20 ?? ?? 02 00 54 12 ?? ?? 22 00 ?? ?? 70 10 ?? ?? 00 00 6e 20 ?? ?? 02 00 54 12 ?? ?? 22 00 ?? ?? 70 20 ?? ?? 10 00 6e 20 ?? ?? 02 00 6e 10 ?? ?? 01 00 0c 02 54 10 ?? ?? 71 20 ?? ?? 02 00 54 12 ?? ?? 1a 00 ?? ?? 6e 20 ?? ?? 02 00}  //weight: 10, accuracy: Low
        $x_5_3 = {70 73 3a 2f 2f 64 [0-23] 2e 63 6c 6f 75 64 66 72 6f 6e 74 2e 6e 65 74 2f 63 6f 6d 2e [0-53] 2e 68 74 6d 6c}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_5_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_AndroidOS_GriftHorse_J_2147814200_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/GriftHorse.J!MTB"
        threat_id = "2147814200"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "GriftHorse"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {03 00 0c 03 12 10 6e 20 ?? ?? 03 00 54 23 [0-21] 22 00 [0-69] 6e 20 ?? ?? 03 00 54 23 [0-21] 22 00 ?? ?? 70 20 [0-16] 6e 20 ?? ?? 03 00 6e 10 ?? ?? 02 00 0c 03 54 20 ?? ?? 71 20 ?? ?? 03 00 54 23 [0-21] 22 00 ?? ?? 70 10 ?? ?? 00 00 1a 01 ?? ?? 6e 20 ?? ?? 10 00 [0-21] 0c 01 6e 20 ?? ?? 10 00 6e 10 ?? ?? 00 00 0c 00 6e 20 ?? ?? 03 00}  //weight: 10, accuracy: Low
        $x_10_2 = {32 00 14 03 ?? ?? ?? 7f 6e 20 ?? ?? 32 00 6e 10 ?? ?? 02 00 0c 03 6e 10 ?? ?? 03 00 6e 10 ?? ?? 02 00 0c 03 1a 00 ?? ?? 12 01 6e 30 ?? ?? 03 01 0a 03 38 03 ?? ?? 6e 10 ?? ?? 02 00 14 03 ?? ?? ?? 7f 6e 20 ?? ?? 32 00 0c 03 1f 03 ?? ?? 6e 10 ?? ?? 03 00 0c 00 12 11 6e 20 ?? ?? 10 00 22 00 ?? ?? 70 10 ?? ?? 00 00 6e 20 ?? ?? 03 00 22 00 ?? ?? 70 10 ?? ?? 00 00 6e 20 ?? ?? 03 00 6e 10 ?? ?? 02 00 0c 00 71 20 ?? ?? 30 00 1a 00 ?? ?? 6e 20 ?? ?? 03 00}  //weight: 10, accuracy: Low
        $x_5_3 = {70 73 3a 2f 2f 64 [0-23] 2e 63 6c 6f 75 64 66 72 6f 6e 74 2e 6e 65 74 2f 63 6f 6d 2e [0-53] 2e 68 74 6d 6c}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_5_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_AndroidOS_GriftHorse_K_2147814201_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/GriftHorse.K!MTB"
        threat_id = "2147814201"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "GriftHorse"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {43 00 14 04 ?? ?? ?? 7f 6e 20 ?? ?? 43 00 14 04 ?? ?? ?? 7f 6e 20 ?? ?? 43 00 0c 04 1f 04 ?? ?? 1a 00 ?? ?? 71 20 ?? ?? 04 00 6e 10 ?? ?? 04 00 0c 00 1a 01 ?? ?? 71 20 ?? ?? 10 00 12 11 6e 20 ?? ?? 10 00 22 00 ?? ?? 70 10 ?? ?? 00 00 6e 20 ?? ?? 04 00 22 00 ?? ?? 70 20 ?? ?? 30 00 1f 00 ?? ?? 6e 20 ?? ?? 04 00 6e 10 ?? ?? 03 00 0c 00 71 20 ?? ?? 40 00 6e 10 ?? ?? 03 00 0c 00 1a 02 ?? ?? 71 20 ?? ?? 20 00 0c 00 38 00 ?? ?? 1a 02 ?? ?? 71 30 ?? ?? 20 01 0a 01 38 01 ?? ?? 1a 00 ?? ?? 22 01 ?? ?? 70 10 ?? ?? 01 00 1a 02 ?? ?? 6e 20 ?? ?? 21 00 6e 20 ?? ?? 01 00 6e 10 ?? ?? 01 00 0c 00 6e 20 ?? ?? 04 00}  //weight: 10, accuracy: Low
        $x_10_2 = {21 00 14 02 ?? ?? 0a 7f 6e 20 ?? ?? 21 00 14 02 ?? ?? 07 7f 6e 20 ?? ?? 21 00 0c 02 1f 02 ?? ?? 5b 12 ?? ?? 6e 10 ?? ?? 02 00 0c 02 12 10 6e 20 ?? ?? 02 00 54 12 ?? ?? 22 00 ?? ?? 70 10 ?? ?? 00 00 6e 20 ?? ?? 02 00 54 12 ?? ?? 22 00 ?? ?? 70 10 ?? ?? 00 00 6e 20 ?? ?? 02 00 6e 10 ?? ?? 01 00 0c 02 54 10 ?? ?? 71 20 ?? ?? 02 00}  //weight: 10, accuracy: Low
        $x_10_3 = {21 00 14 02 ?? ?? 0c 7f 6e 20 ?? ?? 21 00 14 02 ?? ?? 09 7f 6e 20 ?? ?? 21 00 0c 02 1f 02 ?? ?? 5b 12 ?? ?? 6e 10 ?? ?? 02 00 0c 02 12 10 6e 20 ?? ?? 02 00 54 12 ?? ?? 22 00 ?? ?? 70 10 ?? ?? 00 00 6e 20 ?? ?? 02 00 54 12 ?? ?? 22 00 ?? ?? 70 20 ?? ?? 10 00 6e 20 ?? ?? 02 00 6e 10 ?? ?? 01 00 0c 02 54 10 ?? ?? 71 20 ?? ?? 02 00 54 12 ?? ?? 62 00 ?? ?? 6e 20 ?? ?? 02 00}  //weight: 10, accuracy: Low
        $x_5_4 = {70 73 3a 2f 2f 64 [0-23] 2e 63 6c 6f 75 64 66 72 6f 6e 74 2e 6e 65 74 2f 63 6f 6d 2e [0-53] 2e 68 74 6d 6c}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_5_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_AndroidOS_GriftHorse_M_2147814718_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/GriftHorse.M!MTB"
        threat_id = "2147814718"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "GriftHorse"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4c 63 6f 6d 2f [0-32] 4d 61 69 6e 41 63 74 69 76 69 74 79}  //weight: 1, accuracy: Low
        $x_2_2 = {70 73 3a 2f 2f 64 [0-23] 2e 63 6c 6f 75 64 66 72 6f 6e 74 2e 6e 65 74 2f 63 6f 6d 2e [0-53] 2e 68 74 6d 6c}  //weight: 2, accuracy: Low
        $x_1_3 = "shouldOverrideUrlLoading" ascii //weight: 1
        $x_1_4 = "registerAndGetInstance" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_AndroidOS_GriftHorse_L_2147814719_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/GriftHorse.L!MTB"
        threat_id = "2147814719"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "GriftHorse"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {43 00 14 04 ?? ?? 0b 7f 6e 20 ?? ?? 43 00 14 04 ?? ?? 08 7f 6e 20 ?? ?? 43 00 0c 04 1f 04 ?? ?? 5b 34 ?? ?? 6e 10 ?? ?? 04 00 0c 04 12 10 6e 20 ?? ?? 04 00 54 34 ?? ?? 22 00 ?? ?? 70 10 ?? ?? 00 00 6e 20 ?? ?? 04 00 54 34 ?? ?? 22 00 ?? ?? 70 20 ?? ?? 30 00 6e 20 ?? ?? 04 00 6e 10 ?? ?? 03 00 0c 04 54 30 ?? ?? 71 20 ?? ?? 04 00 6e 10 ?? ?? 03 00 0c 04 1a 00 ?? ?? 71 20 ?? ?? 04 00 0c 04 54 30 [0-40] 54 32 ?? ?? 6e 20 ?? ?? 21 00 6e 20 ?? ?? 41 00 6e 10 ?? ?? 01 00 0c 04 6e 20 ?? ?? 40 00}  //weight: 10, accuracy: Low
        $x_10_2 = {32 00 14 03 ?? ?? 0a 7f 6e 20 ?? ?? 32 00 14 03 ?? ?? 07 7f 6e 20 ?? ?? 32 00 0c 03 1f 03 ?? ?? 6e 10 ?? ?? 03 00 0c 00 12 11 6e 20 ?? ?? 10 00 22 00 ?? ?? 70 20 ?? ?? 20 00 6e 20 ?? ?? 03 00 22 00 ?? ?? 70 20 ?? ?? 20 00 6e 20 ?? ?? 03 00 6e 10 ?? ?? 02 00 0c 00 71 20 ?? ?? 30 00 [0-5] 6e 20 ?? ?? 03 00}  //weight: 10, accuracy: Low
        $x_10_3 = {0c 00 60 01 ?? ?? 6e 20 ?? ?? 13 00 0c 01 1f 01 ?? ?? 71 20 ?? ?? 10 00 60 00 ?? ?? 6e 20 ?? ?? 03 00 0c 00 1f 00 ?? ?? 22 01 ?? ?? 70 10 ?? ?? 01 00 1a 02 ?? ?? 6e 20 ?? ?? 21 00 6e 20 ?? ?? 41 00 6e 10 ?? ?? 01 00 0c 04 6e 20 ?? ?? 40 00}  //weight: 10, accuracy: Low
        $x_5_4 = {70 73 3a 2f 2f 64 [0-23] 2e 63 6c 6f 75 64 66 72 6f 6e 74 2e 6e 65 74 2f 63 6f 6d 2e [0-53] 2e 68 74 6d 6c}  //weight: 5, accuracy: Low
        $x_5_5 = "liteoffersapps-eu.s3.eu-central-1.amazonaws.com/com.turbo.fungames.html" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_5_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_AndroidOS_GriftHorse_O_2147815617_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/GriftHorse.O!MTB"
        threat_id = "2147815617"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "GriftHorse"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4c 63 6f 6d 2f [0-87] 53 70 6c 61 73 68 41 63 74 69 76 69 74 79}  //weight: 1, accuracy: Low
        $x_1_2 = ".cloudfront.net" ascii //weight: 1
        $x_1_3 = {21 00 71 00 [0-4] 00 00 0c 02 6e 20 [0-4] 12 00 0c 02 6e 10 [0-4] 01 00 0c 00 6e 20 [0-4] 02 00 0c 02 54 10 [0-4] 6e 20 [0-4] 02 00 0c 02 54 10 [0-4] 6e 20 [0-4] 02 00 0c 02 54 10 [0-4] 6e 20 [0-4] 02 00 0c 02 6e 20 [0-4] 12 00 6e 10 [0-4] 01 00}  //weight: 1, accuracy: Low
        $x_1_4 = "getContentResolver" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_GriftHorse_P_2147815618_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/GriftHorse.P!MTB"
        threat_id = "2147815618"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "GriftHorse"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {21 00 12 12 6e 20 [0-4] 21 00 6e 10 [0-4] 01 00 0c 02 13 00 00 04 6e 30 [0-4] 02 00 14 02 [0-4] 7f 6e 20 [0-4] 21 00 71 00 [0-4] 00 00 0c 02 6e 20 [0-4] 12 00 0c 02 6e 10 [0-4] 01 00 0c 00 6e 20 [0-4] 02 00 0c 02 14 00 [0-4] 7f 6e 20 [0-4] 01 00 0c 00 6e 20 [0-4] 02 00 0c 02 1a 00 [0-4] 6e 20 [0-4] 02 00 0c 02 1a 00 [0-4] 6e 20 [0-4] 02 00 0c 02 1a 00 [0-4] 6e 20 [0-4] 02 00 0c 02 6e 20 [0-4] 12 00 6e 10 [0-4] 01 00}  //weight: 1, accuracy: Low
        $x_1_2 = "getContentResolver" ascii //weight: 1
        $x_1_3 = "Lcom/generalflow/bridge" ascii //weight: 1
        $x_1_4 = ".cloudfront.net" ascii //weight: 1
        $x_1_5 = "WebChromeClient" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_GriftHorse_Q_2147820417_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/GriftHorse.Q!MTB"
        threat_id = "2147820417"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "GriftHorse"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "provideChromeCustomTabsComponent" ascii //weight: 1
        $x_1_2 = "provideStartComponent" ascii //weight: 1
        $x_1_3 = "injectMytrackerService" ascii //weight: 1
        $x_1_4 = "injectOnesignalService" ascii //weight: 1
        $x_1_5 = "injectAppsflyerService" ascii //weight: 1
        $x_1_6 = "injectSimpleWebViewPresenter" ascii //weight: 1
        $x_1_7 = "getSuperUrlService" ascii //weight: 1
        $x_1_8 = "getStartUriService" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_AndroidOS_GriftHorse_C_2147849756_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/GriftHorse.C"
        threat_id = "2147849756"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "GriftHorse"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "&sub_id_8={clickKey}&" ascii //weight: 2
        $x_2_2 = "nbmbteslerbomnb" ascii //weight: 2
        $x_2_3 = "AppsFinit" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

