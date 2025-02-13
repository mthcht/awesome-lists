rule Trojan_MSIL_Stimilini_H_2147691373_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stimilini.H"
        threat_id = "2147691373"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stimilini"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "SteamStealerExtreme" ascii //weight: 5
        $x_1_2 = ".Item>>.GetEnumerator" ascii //weight: 1
        $x_1_3 = ".Item>>.get_Current" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stimilini_H_2147691373_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stimilini.H"
        threat_id = "2147691373"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stimilini"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_9_1 = {00 53 74 65 61 6d 53 74 65 61 6c 65 72 45 78 74 72 65 6d 65}  //weight: 9, accuracy: High
        $x_1_2 = {00 73 74 65 61 6d 43 6f 6f 6b 69 65 73 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 53 74 65 61 6d 50 72 6f 66 69 6c 65 00}  //weight: 1, accuracy: High
        $x_1_4 = {00 47 65 74 53 74 65 61 6d 49 74 65 6d 73 00}  //weight: 1, accuracy: High
        $x_1_5 = {00 53 74 65 61 6d 57 65 62 52 65 71 75 65 73 74 00}  //weight: 1, accuracy: High
        $x_1_6 = {00 6d 5f 44 65 63 6f 64 65 72 73 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_9_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Stimilini_A_2147692652_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stimilini.gen!A"
        threat_id = "2147692652"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stimilini"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "DeathByCaptcha" ascii //weight: 1
        $x_1_2 = "/recaptcha/api/fallback?k=6LdlRgAT" ascii //weight: 1
        $x_1_3 = "steamcommunity.com/" ascii //weight: 1
        $x_1_4 = "&ui_mode=web&access_token=" ascii //weight: 1
        $x_1_5 = "&tradeoffermessage={0}&json_tradeoffer=" ascii //weight: 1
        $x_1_6 = "7656119[0-9]{10}%7c%7c[A-F0-9]{40}" ascii //weight: 1
        $x_1_7 = {63 6d 64 2e 65 78 65 ?? ?? ?? ?? ?? 73 74 61 72 74 20 22 22 20 22 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 72 75 6e 61 73}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stimilini_A_2147692652_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stimilini.gen!A"
        threat_id = "2147692652"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stimilini"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "765611[0-9]{11}%7c%7c[A-F0-9]{40}" ascii //weight: 1
        $x_1_2 = "steamcommunity.com/" ascii //weight: 1
        $x_1_3 = "/api.php?act=log&user=" ascii //weight: 1
        $x_1_4 = "&callback=angular.callbacks" ascii //weight: 1
        $x_1_5 = {73 74 65 61 6d 73 74 65 61 6c 65 72 2e 63 6f 6d [0-21] 5c 64 61 74 61 2e 7a 69 70}  //weight: 1, accuracy: Low
        $x_1_6 = {63 6d 64 2e 65 78 65 ?? ?? ?? ?? ?? 73 74 61 72 74 20 22 22 20 22 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 72 75 6e 61 73}  //weight: 1, accuracy: Low
        $x_1_7 = {5c 63 6f 6e 66 69 67 [0-8] 63 6f 6e 66 69 67 2e 76 64 66}  //weight: 1, accuracy: Low
        $x_1_8 = "{1}{0}User - {2}{0}Pass" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule Trojan_MSIL_Stimilini_J_2147694143_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stimilini.J"
        threat_id = "2147694143"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stimilini"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {00 73 74 65 61 6d 77 65 62 68 65 6c 70 65 72}  //weight: 2, accuracy: High
        $x_1_2 = {00 67 65 74 5f 4d 61 72 6b 65 74 5f 4e 61 6d 65 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 67 65 74 5f 52 67 49 6e 76 65 6e 74 6f 72 79 00}  //weight: 1, accuracy: High
        $x_1_4 = {00 67 65 74 5f 54 72 61 64 61 62 6c 65 00}  //weight: 1, accuracy: High
        $x_1_5 = {00 52 65 73 6f 6c 76 65 53 69 67 6e 61 74 75 72 65 00}  //weight: 1, accuracy: High
        $x_1_6 = {00 55 6e 61 75 74 68 6f 72 69 7a 65 64 41 63 63 65 73 73 45 78 63 65 70 74 69 6f 6e 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stimilini_K_2147694660_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stimilini.K"
        threat_id = "2147694660"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stimilini"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "loginMove" ascii //weight: 1
        $x_1_2 = "HideMove" ascii //weight: 1
        $x_1_3 = "\\Steam.pdb" ascii //weight: 1
        $x_3_4 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 [0-24] 2e 00 [0-4] 2f 00 64 00 61 00 74 00 61 00 2f 00 65 00 6e 00 74 00 72 00 79 00 2f 00 64 00 61 00 74 00 61 00 2e 00 70 00 68 00 70 00}  //weight: 3, accuracy: Low
        $x_3_5 = {68 74 74 70 3a 2f 2f [0-24] 2e [0-4] 2f 64 61 74 61 2f 65 6e 74 72 79 2f 64 61 74 61 2e 70 68 70}  //weight: 3, accuracy: Low
        $x_3_6 = "2.35.92.75" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Stimilini_L_2147694673_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stimilini.L"
        threat_id = "2147694673"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stimilini"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "InventoryItem" ascii //weight: 1
        $x_1_2 = "SendToTrade" ascii //weight: 1
        $x_1_3 = "SLogin" ascii //weight: 1
        $x_1_4 = "SteamSession" ascii //weight: 1
        $x_2_5 = "recaptcha" ascii //weight: 2
        $x_5_6 = "PokeSS.dll" ascii //weight: 5
        $x_10_7 = "://pokestealer.com" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Stimilini_M_2147694992_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stimilini.M"
        threat_id = "2147694992"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stimilini"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "SteamPath" wide //weight: 2
        $x_4_2 = ":\\Steam.exe" wide //weight: 4
        $x_6_3 = {2f 00 2f 00 64 00 6f 00 63 00 73 00 2e 00 67 00 6f 00 6f 00 67 00 6c 00 65 00 2e 00 63 00 6f 00 6d 00 2f 00 75 00 63 00 3f 00 61 00 75 00 74 00 68 00 75 00 73 00 65 00 72 00 3d 00 30 00 26 00 69 00 64 00 3d 00 30 00 42 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 26 00 65 00 78 00 70 00 6f 00 72 00 74 00 3d 00 64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00}  //weight: 6, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stimilini_M_2147694992_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stimilini.M"
        threat_id = "2147694992"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stimilini"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "SteamPath" wide //weight: 2
        $x_4_2 = ":\\Steam.exe" ascii //weight: 4
        $x_6_3 = {61 00 75 00 74 00 68 00 75 00 73 00 65 00 72 00 3d 00 30 00 26 00 69 00 64 00 3d 00 30 00 42 00 78 00 41 00 48 00 48 00 32 00 63 00 68 00 4b 00 36 00 2d 00 49 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 26 00 65 00 78 00 70 00 6f 00 72 00 74 00 3d 00 64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00}  //weight: 6, accuracy: Low
        $x_6_4 = {61 75 74 68 75 73 65 72 3d 30 26 69 64 3d 30 42 78 41 48 48 32 63 68 4b 36 2d 49 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 26 65 78 70 6f 72 74 3d 64 6f 77 6e 6c 6f 61 64}  //weight: 6, accuracy: Low
        $x_6_5 = {3a 00 2f 00 2f 00 67 00 61 00 6d 00 65 00 65 00 6e 00 69 00 78 00 66 00 69 00 6c 00 65 00 73 00 2e 00 72 00 75 00 2f 00 53 00 74 00 65 00 61 00 6d 00 [0-4] 2e 00 65 00 78 00 65 00}  //weight: 6, accuracy: Low
        $x_6_6 = {3a 2f 2f 67 61 6d 65 65 6e 69 78 66 69 6c 65 73 2e 72 75 2f 53 74 65 61 6d [0-4] 2e 65 78 65}  //weight: 6, accuracy: Low
        $x_6_7 = "://poseidontv00123.esy.es" wide //weight: 6
        $x_6_8 = "://docs.google.com/uc?authuser=0&id=0B6tI8Ts5WR3aRFg0WTEyQlBSVVk&export=download" wide //weight: 6
        $x_6_9 = "://docs.google.com/uc?authuser=0&id=0B0bSTjbZdzF1bjFPN0g1YThqSFk&export=download" wide //weight: 6
        $x_6_10 = "://docs.google.com/uc?authuser=0&id=0B4lKdpVaR2TEbkNiMzRlenBjTzA&export=download" wide //weight: 6
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_6_*) and 1 of ($x_4_*) and 1 of ($x_2_*))) or
            ((2 of ($x_6_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Stimilini_N_2147695064_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stimilini.N"
        threat_id = "2147695064"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stimilini"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "26"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "get_Password" ascii //weight: 1
        $x_5_2 = "://ge.tt/api/1/files/8iLPmr92/0/blob?download" wide //weight: 5
        $x_5_3 = "://ge.tt/api/1/files/208Agr92/0/blob?download" wide //weight: 5
        $x_5_4 = "://ge.tt/api/1/files/4oOBHr92/0/blob?download" wide //weight: 5
        $x_20_5 = "HollyMolly.Properties.Resources" wide //weight: 20
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 1 of ($x_5_*) and 1 of ($x_1_*))) or
            ((1 of ($x_20_*) and 2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Stimilini_G_2147705979_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stimilini.G"
        threat_id = "2147705979"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stimilini"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Login_Data_Path" ascii //weight: 1
        $x_1_2 = "Games\\FuckEngine" ascii //weight: 1
        $x_1_3 = "\\Steam.pdb" ascii //weight: 1
        $x_1_4 = "Steam Client Bootstrapper" ascii //weight: 1
        $x_1_5 = ".ru/steam/" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

