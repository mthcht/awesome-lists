rule Trojan_Win32_Konus_SG_2147779259_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Konus.SG!MTB"
        threat_id = "2147779259"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Konus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "52"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "data_inject" ascii //weight: 20
        $x_1_2 = "[TAB]" ascii //weight: 1
        $x_1_3 = "[DELETE]" ascii //weight: 1
        $x_1_4 = "[BACKSPACE]" ascii //weight: 1
        $x_1_5 = "[RETURN]" ascii //weight: 1
        $x_5_6 = {00 46 33 50 37 59 36 50 33 55 33 45 32 55 35 46 33 00}  //weight: 5, accuracy: High
        $x_5_7 = {00 50 34 59 37 54 37 52 37 52 38 58 33 45 33 41 33 00}  //weight: 5, accuracy: High
        $x_5_8 = {00 44 33 53 30 41 37 52 34 46 36 43 38 46 32 52 35 00}  //weight: 5, accuracy: High
        $x_10_9 = ":Zone.Identifier" wide //weight: 10
        $x_10_10 = "profiles.ini" wide //weight: 10
        $x_10_11 = "\\Google\\Chrome\\User Data\\Default\\" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 2 of ($x_10_*) and 2 of ($x_5_*) and 2 of ($x_1_*))) or
            ((1 of ($x_20_*) and 2 of ($x_10_*) and 3 of ($x_5_*))) or
            ((1 of ($x_20_*) and 3 of ($x_10_*) and 2 of ($x_1_*))) or
            ((1 of ($x_20_*) and 3 of ($x_10_*) and 1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Konus_SH_2147779260_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Konus.SH!MTB"
        threat_id = "2147779260"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Konus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "63"
        strings_accuracy = "High"
    strings:
        $x_30_1 = "C3E0Q6R7F1H2G5A4" ascii //weight: 30
        $x_1_2 = "https://api.ipify.org/" ascii //weight: 1
        $x_1_3 = "?a=0" ascii //weight: 1
        $x_1_4 = "?a=4" ascii //weight: 1
        $x_1_5 = "?a=2" ascii //weight: 1
        $x_1_6 = "?a=3" ascii //weight: 1
        $x_10_7 = ":Zone.Identifier" wide //weight: 10
        $x_10_8 = "SeDebugPrivilege" wide //weight: 10
        $x_10_9 = "chrome.exe" wide //weight: 10
        $x_10_10 = "explorer.exe" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_30_*) and 3 of ($x_10_*) and 3 of ($x_1_*))) or
            ((1 of ($x_30_*) and 4 of ($x_10_*))) or
            (all of ($x*))
        )
}

