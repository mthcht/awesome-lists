rule Trojan_MacOS_Xcsset_A_2147762225_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Xcsset.A!MTB"
        threat_id = "2147762225"
        type = "Trojan"
        platform = "MacOS: "
        family = "Xcsset"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 43 48 48 c7 43 30 01 00 00 00 48 b8 6d 65 74 68 6f 64 00 00 48 89 43 50 4c 89 7b 58 4c 89 63 78 48 b8 50 61 67 65 2e 67 65 74 48 89 43 60 48 b8 43 6f 6f 6b 69 65 73 ef 48 89 43 68 48 89 df}  //weight: 1, accuracy: High
        $x_2_2 = {48 89 c3 0f 28 05 ?? ?? ?? 00 0f 11 40 10 48 b8 65 78 70 72 65 73 73 69 48 89 43 20 48 b8 6f 6e 00 00 00 00 00 ea 48 89 43 28 4c 89 73 48 48 8b 45 c0 48 89 43 30 4c 8b ?? ?? 4c 89 ?? ?? 48 b8 73 69 6c 65 6e 74 00 00 48 89 43 50 4c 89 ?? 58 48 8b 05 ?? ?? 04 00 48 89 43 78 c6 43 60 01 48 89 df}  //weight: 2, accuracy: Low
        $x_1_3 = {48 b8 65 63 68 6f 20 27 00 00 48 89 45 c0 48 b8 00 00 00 00 00 00 00 e6 48 89 45 c8 4c 8d 6d c0 48 8b bd 58 ff ff ff 48 8b 75 80 e8 8e 28 00 00 48 bf 27 20 3e 20 27 00 00 00 48 be 00 00 00 00 00 00 00 e5 e8 75 28 00 00 4c 8b 7d 90 4c 89 ff 4c 8b 65 b0 4c 89 e6 e8 62 28 00 00 bf 27 00 00 00 48 be 00 00 00 00 00 00 00 e1 e8 4e 28 00 00 48 8b 7d c0 48 8b 5d c8 48 89 de e8 0a ee ff ff 49 89 d6 48 89 df e8 9b 2c 00 00 4c 89 f7 e8 93 2c 00 00 48 b8 63 68 6d 6f 64 20 2b 78 48 89 45 c0 48 b8 20 27 00 00 00 00 00 ea 48 89 45 c8}  //weight: 1, accuracy: High
        $x_1_4 = {49 8b 7c 24 30 48 85 ff 0f 84 a1 2c 00 00 49 bf 00 00 00 00 00 00 00 e8 49 8b 44 24 28 48 89 85 90 fd ff ff 48 89 bd 98 fd ff ff 48 b8 70 61 79 70 61 6c 2e 63 48 89 85 d0 fd ff ff 48 b8 6f 6e 00 00 00 00 00 ea 48 05 00 ff ff ff 48 89 85 d8 fd ff ff}  //weight: 1, accuracy: High
        $x_1_5 = "Network.getAllCookies" ascii //weight: 1
        $x_1_6 = {62 6c 65 20 2d 73 74 72 69 6e 67 [0-16] 42 72 6f 77 73 65 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MacOS_Xcsset_A_2147815025_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Xcsset.A!xp"
        threat_id = "2147815025"
        type = "Trojan"
        platform = "MacOS: "
        family = "Xcsset"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {73 65 63 75 72 69 74 79 2e 63 73 70 2e 65 6e 61 62 6c 65 [0-3] 66 61 6c 73 65}  //weight: 1, accuracy: Low
        $x_1_2 = "user_pref(\"devtools.debugger.remote-enabled" ascii //weight: 1
        $x_1_3 = "killall -9 'firefox' 2> /dev/null" ascii //weight: 1
        $x_1_4 = "/apple/agentd.php" ascii //weight: 1
        $x_1_5 = "Executed paypal payloads" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_MacOS_Xcsset_C_2147822823_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Xcsset.C!MTB"
        threat_id = "2147822823"
        type = "Trojan"
        platform = "MacOS: "
        family = "Xcsset"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 05 19 7e 00 00 89 c1 48 8d 15 1e 7e 00 00 40 8a 34 0a 40 88 75 f3 0f b6 45 f3 0f b6 3d fb 7d 00 00 01 c7 40 88 3d f2 7d 00 00 48 8b 4d e8 0f b6 05 e9 7d 00 00 48 89 55 e0 99 f7 7d f4 4c 63 c2 42 0f b6 14 01 44 0f b6 0d cf 7d 00 00 41 01 d1 44 88 0d c5 7d 00 00 0f b6 15 be 7d 00 00 89 d1 4c 8b 45 e0 41 8a 34 08 0f b6 15 af 7d 00 00 89 d1 41 88 34 08 40 8a 75 f3 0f b6 15 9c 7d 00 00 89 d1 41 88 34 08 8a 05 92 7d 00 00 04 01 88 05 8a 7d 00 00 3c 00 0f 85 62 ff ff ff 48 8b 45 e8 48 05 00 01 00 00 48 89 45 e8 8b 4d f4 81 e9 00 01 00 00 89 4d f4 e9 34 ff ff ff}  //weight: 1, accuracy: High
        $x_1_2 = {8a 05 2f 7d 00 00 04 01 88 05 27 7d 00 00 0f b6 0d 20 7d 00 00 89 ca 48 8d 35 25 7d 00 00 8a 04 16 88 45 f3 0f b6 4d f3 0f b6 3d 05 7d 00 00 01 cf 40 88 3d fc 7c 00 00 0f b6 0d f5 7c 00 00 89 ca 8a 04 16 0f b6 0d ea 7c 00 00 89 ca 88 04 16 8a 45 f3 0f b6 0d da 7c 00 00 89 ca 88 04 16 0f b6 0d cf 7c 00 00 89 ca 0f b6 0c 16 44 0f b6 45 f3 41 01 c8 44 88 45 f3 0f b6 4d f3 89 ca 0f b6 0c 16 48 8b 55 e8 44 0f b6 0a 41 31 c9 44 88 0a 48 8b 55 e8 48 81 c2 01 00 00 00 48 89 55 e8 8b 4d f4 83 c1 ff 89 4d f4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Xcsset_AX_2147933513_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Xcsset.AX"
        threat_id = "2147933513"
        type = "Trojan"
        platform = "MacOS: "
        family = "Xcsset"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/bin/sh -c" wide //weight: 1
        $x_1_2 = "/bin/bash -c" wide //weight: 1
        $x_5_3 = "grep -qF '.zshrc_aliases' ~/.zshrc || echo '[ -f $HOME/.zshrc_aliases ] && . $HOME/.zshrc_aliases' >> ~/.zshrc" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

