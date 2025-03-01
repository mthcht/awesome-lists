rule Trojan_MacOS_NukeSped_A_2147744584_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/NukeSped.A!MTB"
        threat_id = "2147744584"
        type = "Trojan"
        platform = "MacOS: "
        family = "NukeSped"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "beastgoc.com" ascii //weight: 2
        $x_1_2 = "%s/grepmonux.php" ascii //weight: 1
        $x_1_3 = {89 ce 83 e6 0f 42 8a 14 06 30 14 0f 48 ff c1 48 39 c8 75 ec}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_NukeSped_B_2147744636_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/NukeSped.B!MTB"
        threat_id = "2147744636"
        type = "Trojan"
        platform = "MacOS: "
        family = "NukeSped"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "crabbedly.club/board.php" ascii //weight: 1
        $x_1_2 = "craypot.live/board.php" ascii //weight: 1
        $x_1_3 = "indagator.club/board.php" ascii //weight: 1
        $x_1_4 = {0f 10 0c 13 0f 10 54 13 10 0f 10 5c 13 20 0f 10 64 13 30 0f 57 c8 0f 57 d0 0f 11 0c 13 0f 11 54 13 10 0f 57 d8 0f 57 e0 0f 11 5c 13 20 0f 11 64 13 30 48 83 c2 40 48 83 c6 02 75 c4 eb 02}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_NukeSped_C_2147745798_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/NukeSped.C!MTB"
        threat_id = "2147745798"
        type = "Trojan"
        platform = "MacOS: "
        family = "NukeSped"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "unioncrypto.vip/update" ascii //weight: 2
        $x_1_2 = "Loader/macos/Barbeque/" ascii //weight: 1
        $x_3_3 = "12GWAPCT1F0I1S14" ascii //weight: 3
        $x_1_4 = "auth_timestamp" ascii //weight: 1
        $x_1_5 = "auth_signature" ascii //weight: 1
        $x_1_6 = {48 8d 55 a8 e8 ?? ?? ?? ?? 83 f8 01 0f 85 9b 00 00 00 48 8b 7d a8 48 8d 35 41 0f 00 00 ba 03 00 00 00 e8 ?? ?? ?? ?? 48 85 c0 0f 84 a4 00 00 00 48 89 c6 b8 f5 ff ff ff 83 fb 02 0f 85 ec 00 00 00 4c 8d 75 a0 ba 04 00 00 00 b9 01 00 00 00 48 89 f7 4c 89 f6 e8 ?? ?? ?? ?? 4d 8b 06 41 8b 40 10}  //weight: 1, accuracy: Low
        $x_1_7 = {be ff 01 00 00 48 89 df e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 83 38 02 75 da 81 3b cf fa ed fe 75 d2 49 89 1e 31 c0 48 83 c4 08 5b 41 5c 41 5d 41 5e 41 5f 5d c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_MacOS_NukeSped_D_2147756370_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/NukeSped.D!MTB"
        threat_id = "2147756370"
        type = "Trojan"
        platform = "MacOS: "
        family = "NukeSped"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "coingotrade.com/update_coingotrade.php" ascii //weight: 1
        $x_1_2 = "/private/tmp/updatecoingotrade" ascii //weight: 1
        $x_1_3 = "isDownload" ascii //weight: 1
        $x_1_4 = "kupay_updater_mac_new" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_NukeSped_D_2147756370_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/NukeSped.D!MTB"
        threat_id = "2147756370"
        type = "Trojan"
        platform = "MacOS: "
        family = "NukeSped"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {45 89 ca 41 83 e2 e0 49 8d 5a e0 48 89 d8 48 c1 e8 05 48 ff c0 41 89 c3 41 83 e3 01 48 85 db 0f 84 a0 00 00 00 4c 89 db 48 29 c3 31 c0 0f 28 05 cd 3b 00 00 66 2e 0f 1f 84 00 00 00 00 00 0f 1f 00}  //weight: 1, accuracy: High
        $x_1_2 = {0f 10 0c 01 0f 10 54 01 10 0f 10 5c 01 20 0f 10 64 01 30 0f 57 c8 0f 57 d0 0f 11 0c 01 0f 11 54 01 10 0f 57 d8 0f 57 e0 0f 11 5c 01 20 0f 11 64 01 30 48 83 c0 40 48 83 c3 02 75 c4 4d 85 db 74 1f}  //weight: 1, accuracy: High
        $x_1_3 = "/bin/bash -c" ascii //weight: 1
        $x_1_4 = "_webident_f" ascii //weight: 1
        $x_1_5 = "_webident_s" ascii //weight: 1
        $x_2_6 = "fudcitydelivers.com/net.php" ascii //weight: 2
        $x_2_7 = "sctemarkets.com/net.php" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MacOS_NukeSped_E_2147775406_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/NukeSped.E!MTB"
        threat_id = "2147775406"
        type = "Trojan"
        platform = "MacOS: "
        family = "NukeSped"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {34 11 48 63 f6 8b b4 b5 e0 fe ff ff 31 b4 95 d0 fe ff ff 48 ff c2 48 39 d0 75 e4}  //weight: 1, accuracy: High
        $x_2_2 = {48 81 ec d8 00 00 00 49 89 d5 49 89 f7 49 89 fc 48 8b 05 3d 14 00 00 48 8b 00 48 89 45 d0 8b 0d 88 17 00 00 83 f9 ff 75 20 48 8d 3d 00 0e 00 00 48 8d b5 40 ff ff ff ?? ?? ?? ?? ?? 31 c9 85 c0 0f 95 c1 89 0d 63 17 00 00}  //weight: 2, accuracy: Low
        $x_1_3 = "qnalytica.com/wp-rss.php" ascii //weight: 1
        $x_1_4 = "Barbeque::~Barbeque()" ascii //weight: 1
        $x_1_5 = "curl_easy_getinfo" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MacOS_NukeSped_F_2147775470_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/NukeSped.F!MTB"
        threat_id = "2147775470"
        type = "Trojan"
        platform = "MacOS: "
        family = "NukeSped"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "://kupaywallet.com/kupay_update.php" ascii //weight: 2
        $x_1_2 = "/private/tmp/kupay_update" ascii //weight: 1
        $x_1_3 = "CoinGo_Trade" ascii //weight: 1
        $x_2_4 = "://23.152.0.101:8080" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

