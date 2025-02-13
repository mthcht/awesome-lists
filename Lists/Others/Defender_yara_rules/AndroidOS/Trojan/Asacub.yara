rule Trojan_AndroidOS_Asacub_B_2147783912_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Asacub.B"
        threat_id = "2147783912"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Asacub"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 20 0a 5c 01 30 00 2a fb d1 41 1e 01 29 0b db df f8 ?? ?? 00 21 7a 44 12 68 53 5c ?? 33 53 54 8b 1c 01 31 83 42 f8 d1 df f8 ?? ?? 00 20 79 44 09 68 0a 5c 01 30 00 2a fb d1 41 1e 01 29 0b db df f8 ?? ?? 00 21 7a 44 12 68 53 5c ?? 33 53 54 8b 1c 01 31 83 42 f8 d1 df f8 ?? ?? 00 20 79 44 09 68 0a 5c 01 30 00 2a fb d1 41 1e 01 29 0b db}  //weight: 2, accuracy: Low
        $x_2_2 = {03 af 4d f8 04 8d 04 46 13 48 90 46 22 68 78 44 05 68 20 46 92 69 55 f8 21 10 90 47 06 46 20 68 55 f8 28 20 31 46 d5 f8 e4 36 d0 f8 40 52 20 46 a8 47 02 46 20 68 31 46 d0 f8 58 32 20 46 98 47 05 46 20 68 31 46 c2 6d 20 46 90 47 28 46}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Asacub_C_2147787842_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Asacub.C"
        threat_id = "2147787842"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Asacub"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {39 05 03 00 0e 00 71 00 ?? ?? 00 00 0a 00 12 01 38 00 ?? ?? 71 10 ?? ?? 05 00 0c 00 71 20 ?? ?? 04 00 0a 00 38 00 ?? ?? 6a 01 ?? ?? 63 00 ?? ?? 38 00 ?? ?? 63 00 ?? ?? 38 00 ?? ?? 63 00 ?? ?? 39 00 48 00 63 00 ?? ?? 38 00 44 00 71 10 ?? ?? 05 00 0c 00 71 20 ?? ?? 04 00 0c 00 71 10 ?? ?? 00 00 0a 02 3d 02 ?? ?? 71 10 ?? ?? 00 00 0a 02 38 ?? ?? 00 71 10 ?? ?? 05 00 0c 02 38 02 ?? ?? 62 03 ?? ?? 71 30 ?? ?? 34 02 0a 03 39 03 ?? ?? 62 03 ?? ?? 71 30 ?? ?? 34 02 0a 03 39 03 ?? ?? 62 03 ?? ?? 71 30 ?? ?? 34 02 0a 02 38 02 03 00 12 11 39 01 06 00 71 10 ?? ?? 00 00 0a 01 38 01 ?? ?? 12 21 71 20 ?? ?? 14 00 71 30 ?? ?? 54 00}  //weight: 3, accuracy: Low
        $x_3_2 = {39 09 03 00 0e 00 12 04 13 06 0f 00 12 07 71 30 ?? ?? 76 04 0c 00 1f 00 ?? ?? 6e 10 ?? ?? 00 00 0a 00 12 01 38 00 2b 00 12 14 23 44 ?? ?? 12 06 4d 09 04 06 13 06 10 00 12 07 71 30 ?? ?? 76 04 0c 00 1f 00 ?? ?? 12 24 23 44 ?? ?? 12 06 4d 08 04 06 12 16 4d 00 04 06 13 06 11 00 12 07 71 30 ?? ?? 76 04 0c 00 1f 00 ?? ?? 6e 10 ?? ?? 00 00 0a 00 38 00 04 00 6a 01 ?? ?? 63 00 ?? ?? 38 00 ff 00 63 00 ?? ?? 38 00 fb 00 63 00 ?? ?? 39 00 f7 00 63 00 ?? ?? 38 00 f3 00 12 14 23 44 ?? ?? 12 06 4d 09 04 06 13 06 12 00 12 07 71 30 ?? ?? 76 04 0c 00 1f 00 ?? ?? 12 24 23 44 ?? ?? 12 06 4d 08 04 06 12 16 4d 00 04 06 13 06 13 00 12 07 71 30 ?? ?? 76 04 0c 00 1f 00 ?? ?? 12 14 23 44 ?? ?? 12 06 4d 00 04}  //weight: 3, accuracy: Low
        $x_3_3 = {00 00 0a 00 12 01 38 00 0e 00 6e 10 ?? ?? 05 00 0c 00 70 20 ?? ?? 04 00 0a 00 38 00 04 00 6a 01 ?? ?? 63 00 ?? ?? 38 00 50 00 63 00 ?? ?? 38 00 4c 00 63 00 ?? ?? 39 00 48 00 63 00 ?? ?? 38 00 44 00 6e 10 ?? ?? 05 00 0c 00 70 20 ?? ?? 04 00 0c 00 6e 10 ?? ?? 00 00 0a 02 3d 02 33 00 71 10 ?? ?? 00 00 0a 02 38 02 21 00 6e 10 ?? ?? 05 00 0c 02 38 02 1b 00 62 03 ?? ?? 70 30 ?? ?? 34 02 0a 03 39 03 12 00 62 03 ?? ?? 70 30 ?? ?? 34 02 0a 03 39 03 0a 00 62 03 ?? ?? 70 30 ?? ?? 34 02 0a 02 38 02 03 00 12 11 39 01 06 00 71 10 ?? ?? 00 00 0a 01 38 01 06 00 12 21 6e 20 ?? ?? 14 00 70 30 ?? ?? 54 00}  //weight: 3, accuracy: Low
        $x_3_4 = {05 00 0c 02 [0-10] 38 02 ?? ?? [0-10] 62 03 ?? ?? [0-10] 70 30 ?? ?? 34 02 0a 03 [0-10] 39 03 ?? ?? [0-10] 62 03 ?? ?? [0-10] 70 30 ?? ?? 34 02 0a 03 [0-10] 39 03 ?? ?? [0-10] 62 03 ?? ?? [0-10] 70 30 ?? ?? 34 02 0a 02 [0-10] 38 02 ?? ?? [0-10] 12 11 [0-10] 39 01 ?? ?? [0-10] 71 10 ?? ?? 00 00 0a 01 [0-10] 38 01 ?? ?? [0-10] 12 21 [0-10] 6e 20 ?? ?? 14 00 [0-10] 70 30 ?? ?? 54 00}  //weight: 3, accuracy: Low
        $x_1_5 = "enabled_accessibility_services" ascii //weight: 1
        $x_1_6 = "getDefaultSms" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Trojan_AndroidOS_Asacub_D_2147787843_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Asacub.D"
        threat_id = "2147787843"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Asacub"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {05 00 0c 00 [0-10] 71 20 ?? ?? 04 00 0a 00 [0-10] 38 00 ?? ?? [0-10] 6a 01 ?? ?? [0-10] 63 00 ?? ?? [0-10] 38 00 ?? ?? [0-10] 63 00 ?? ?? [0-10] 38 00 ?? ?? [0-10] 63 00 ?? ?? [0-10] 39 00 ?? ?? [0-10] 63 00 ?? ?? [0-10] 38 00 ?? ?? [0-10] 71 10 ?? ?? 05 00 0c 00 [0-10] 71 20 ?? ?? 04 00 0c 00 [0-10] 71 10 ?? ?? 00 00 0a 02 [0-10] 3d 02 ?? ?? [0-10] 71 10 ?? ?? 00 00 0a 02 [0-10] 38 02 ?? ?? [0-10] 71 10}  //weight: 3, accuracy: Low
        $x_3_2 = {05 00 0c 02 [0-10] 38 02 ?? ?? [0-10] 62 03 ?? ?? [0-10] 71 30 ?? ?? 34 02 0a 03 [0-10] 39 03 ?? ?? [0-10] 62 03 ?? ?? [0-10] 71 30 ?? ?? 34 02 0a 03 [0-10] 39 03 ?? ?? [0-10] 62 03 ?? ?? [0-10] 71 30 ?? ?? 34 02 0a 02 [0-10] 38 02 ?? ?? [0-10] 12 11 [0-10] 39 01 ?? ?? [0-10] 71 10 ?? ?? 00 00 0a 01 [0-10] 38 01 ?? ?? [0-10] 12 21 [0-10] 71 20 ?? ?? 14 00 [0-10] 71 30 ?? ?? 54 00}  //weight: 3, accuracy: Low
        $x_1_3 = "enabled_accessibility_services" ascii //weight: 1
        $x_1_4 = "getDefaultSms" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_AndroidOS_Asacub_E_2147822431_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Asacub.E!MTB"
        threat_id = "2147822431"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Asacub"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "myownbehap" ascii //weight: 1
        $x_1_2 = "com.petty.account" ascii //weight: 1
        $x_1_3 = "RhesseBy" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Asacub_A_2147823669_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Asacub.A!xp"
        threat_id = "2147823669"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Asacub"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "idMethodEP8_jo" ascii //weight: 1
        $x_1_2 = {20 00 29 00 b0 47 02 00 20 00 29 00 02 f0}  //weight: 1, accuracy: High
        $x_1_3 = {00 d0 b5 02 af 0c 4c 0d 49 0d 4b a2 42 00 db 19 00 7d 23 dc 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_AndroidOS_Asacub_A_2147829882_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Asacub.A!MTB"
        threat_id = "2147829882"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Asacub"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {03 af 4d f8 04 8d 04 46 13 48 90 46 22 68 78 44 05 68 20 46 92 69 55 f8 21 10 90 47 06 46 20 68 55 f8 28 20 31 46 d5 f8 e4 36 d0 f8 40 52 20 46 a8 47 02 46 20 68 31 46 d0 f8 58 32 20 46 98 47 05 46 20 68 31 46 c2 6d 20 46 90 47 28 46}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Asacub_B_2147829885_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Asacub.B!MTB"
        threat_id = "2147829885"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Asacub"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {44 00 68 00 68 f1 60 08 60 a9 20 80 00 21 68 0b 58 00 25 b4 60 20 00 11 00 2a 00 98 47 01 78 00 29 30 d0 ea 43 71 60 30 39 ff 24 21 40 6b 1c 0a 29 00 d3 2b 00 81 18 89 78 01 32 00 29 08 b4 20 bc f1 d1 d9 1d 07 23 99 43 6b 46 59 1a 8d 46 00 25 00 2a 1a db 31 61 01 30 70 61 00 20 05 00 71 68 02 e0 71 69 09 5c 18 00 0b 00 30 3b 23 40 09 2b 02 d8 33 69 59 55 01 35 43 1c 90 42 f1 d1 f4 68 31 69 03 e0 00 25 f1 1d 15 31 f4 68 00 20 48 55 a7 20 82 00 b0 68 03 68 9a 58 90 47 07 49 79 44 09 68 09 68 22 68 89 1a 03 d1 fc 1f 05 3c a5 46 f0 bd 01 f0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Asacub_E_2147830714_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Asacub.E"
        threat_id = "2147830714"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Asacub"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "btfe.vtrgx.glbm" ascii //weight: 3
        $x_3_2 = "entryPoint$AutoService" ascii //weight: 3
        $x_3_3 = "akxl.pyctl.gald" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Asacub_C_2147831409_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Asacub.C!MTB"
        threat_id = "2147831409"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Asacub"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "BlockServdfgdgd" ascii //weight: 1
        $x_1_2 = "poomadm" ascii //weight: 1
        $x_1_3 = "dd/aS/dd/ssdfgfdgd/smssixfgdgd/HeadlessSmsSendServic" ascii //weight: 1
        $x_1_4 = "Smsmnd" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Asacub_D_2147831582_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Asacub.D!MTB"
        threat_id = "2147831582"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Asacub"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ru.assumption.have" ascii //weight: 1
        $x_1_2 = "getHintHideIcon" ascii //weight: 1
        $x_1_3 = "PrematureTune" ascii //weight: 1
        $x_1_4 = "YardRestaurant" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

