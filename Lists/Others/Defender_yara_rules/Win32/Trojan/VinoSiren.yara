rule Trojan_Win32_VinoSiren_E_2147741917_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VinoSiren.E!dha"
        threat_id = "2147741917"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VinoSiren"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c1 eb 08 89 5c 24 2c 8b d1 8b d9 c1 ea 08 c1 eb 10 22 da 22 d9 8b c8 c1 e9 10 22 4c 24 2c 89 54 24 14 32 d9 8a d0 22 54 24 28 c1 e8 18 32 da 32 d8 8b 44 24 10 8d 0c 3f 33 cf 81 e1 fe 01 00 00 c1 e0 18 0b 44 24 2c c1 e1 16}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VinoSiren_F_2147741918_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VinoSiren.F!dha"
        threat_id = "2147741918"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VinoSiren"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c1 e8 18 33 d0 8b 4d f8 c1 e9 08 23 4d f8 8b 45 f8 c1 e8 10 23 c8 33 d1 88 55 f7 8b 4d f8 c1 e9 08 8b 55 fc d1 ea 33 55 fc 81 e2 ff 00 00 00 c1 e2 17 0b ca 89 4d 14 8b 45 f8 c1 e0 18 8b 4d fc c1 e9 08}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VinoSiren_I_2147741919_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VinoSiren.I!dha"
        threat_id = "2147741919"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VinoSiren"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "ANONYBR" ascii //weight: 4
        $x_1_2 = "hNMWz33cUbGDp95xzr7DVQ==" ascii //weight: 1
        $x_1_3 = "lIEv82OABO2GppI=" ascii //weight: 1
        $x_1_4 = "joc++n3dU7etuptZ8qDKZw==" ascii //weight: 1
        $x_1_5 = "rIw48WrfBfHMrpJb" ascii //weight: 1
        $x_1_6 = "j50+71zWWKewr49CwqHSZw" ascii //weight: 1
        $x_1_7 = "gIUl/W7faoKshbBu5YDp" ascii //weight: 1
        $x_1_8 = "hJsv/nvWZrGNqZtE1JM=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((7 of ($x_1_*))) or
            ((1 of ($x_4_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_VinoSiren_J_2147741920_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VinoSiren.J!dha"
        threat_id = "2147741920"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VinoSiren"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = "3bcd1fghijklmABCDEFGH-J+LMnopq4stuvwxyzNOPQ7STUVWXYZ0e2ar56R89K/" ascii //weight: 5
        $x_1_2 = {c1 e9 08 8b 55 f8 c1 ea 02 33 55 f8 8b 45 f8 c1 e8 03 33 d0 8b 45 f8 c1 e8 07 33 d0 c1 e2 18 0b ca}  //weight: 1, accuracy: High
        $x_1_3 = {89 45 fc ba 02 00 00 00 8b 45 fc e8 ?? ?? ?? ?? 8b d8 33 5d fc ba 03 00 00 00 8b 45 fc e8 ?? ?? ?? ?? 33 d8 ba 07 00 00 00 8b 45 fc e8 ?? ?? ?? ?? 33 d8 c1 e3 18 ba 08 00 00 00 8b 45 fc e8 ?? ?? ?? ?? 0b d8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_VinoSiren_K_2147741921_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VinoSiren.K!dha"
        threat_id = "2147741921"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VinoSiren"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "@I4You@12!!!" ascii //weight: 1
        $x_1_2 = "\\DM%d%02d%02d.nls" ascii //weight: 1
        $x_1_3 = "### {/CLIPBOARD} ###" ascii //weight: 1
        $x_1_4 = "MyHook Session" ascii //weight: 1
        $x_1_5 = "KB987324.log" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_VinoSiren_L_2147741922_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VinoSiren.L!dha"
        threat_id = "2147741922"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VinoSiren"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SELECT origin_url, username_value, password_value FROM logins" ascii //weight: 1
        $x_1_2 = "SELECT encryptedUsername, encryptedPassword, hostname FROM moz_logins" ascii //weight: 1
        $x_1_3 = "/FileZilla3/RecentServers/Server/*" ascii //weight: 1
        $x_1_4 = "/configuration/root/container/connection/connection_info/*" ascii //weight: 1
        $x_1_5 = "{all,browsers,mails,others}" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

