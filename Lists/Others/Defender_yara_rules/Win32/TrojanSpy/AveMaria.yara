rule TrojanSpy_Win32_AveMaria_BM_2147741698_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/AveMaria.BM"
        threat_id = "2147741698"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "AveMaria"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AVE_MARIA" ascii //weight: 1
        $x_1_2 = "PK11_CheckUserPassword" ascii //weight: 1
        $x_1_3 = "Accounts\\Account.rec0" ascii //weight: 1
        $x_1_4 = "SELECT * FROM logins" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_AveMaria_G_2147744601_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/AveMaria.G!MTB"
        threat_id = "2147744601"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 ca 8b 45 ?? c7 04 81 ?? ?? ?? ?? eb 23 00 8b 55 ?? 83 c2 ?? 89 55 ?? 83 7d ec ?? 7d ?? 69 45 f4 ?? ?? ?? ?? 8d 8c 05 ?? ?? ?? ?? 8b 55 ?? c1 e2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_AveMaria_AR_2147753845_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/AveMaria.AR!MTB"
        threat_id = "2147753845"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "AveMaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f be 14 01 f7 d2 8b 45 84 03 45 80 88 10}  //weight: 1, accuracy: High
        $x_1_2 = {0f be 11 8b 85 ?? ?? ?? ?? 0f be 4c 05 8c 33 d1 8b 45 84 03 85 ?? ?? ?? ?? 88 10}  //weight: 1, accuracy: Low
        $x_1_3 = "SOFTWARE\\Wow6432Node\\Microsoft\\VisualStudio\\14.0\\Setup\\VC" wide //weight: 1
        $x_1_4 = {84 03 55 80 88 0e 00 0f be ?? ?? f7 ?? 8b}  //weight: 1, accuracy: Low
        $x_1_5 = {6c ff ff ff 88 1b 00 0f be ?? 8b ?? 68 ff ff ff 0f be ?? ?? 8c 33 ?? 8b ?? 84 03}  //weight: 1, accuracy: Low
        $x_1_6 = {0f be 0c 10 f7 d1 8b 55 84 03 55 80 88 0a}  //weight: 1, accuracy: High
        $x_1_7 = {0f be 02 8b 8d ?? ?? ?? ?? 0f be 54 0d 8c 33 c2 8b 4d 84 03 8d ?? ?? ?? ?? 88 01 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanSpy_Win32_AveMaria_STA_2147767132_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/AveMaria.STA"
        threat_id = "2147767132"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "AveMaria"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Ave_Maria Stealer" ascii //weight: 2
        $x_1_2 = "wmic process call create" ascii //weight: 1
        $x_1_3 = "powershell Add-MpPreference -ExclusionPath " ascii //weight: 1
        $x_1_4 = "select signon_realm, origin_url, username_value, password_value from wow_logins" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_AveMaria_STB_2147767134_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/AveMaria.STB"
        threat_id = "2147767134"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "AveMaria"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ellocnak.xml" ascii //weight: 1
        $x_1_2 = "Elevation:Administrator!new" ascii //weight: 1
        $x_1_3 = {48 65 79 20 49 27 6d 20 41 64 6d 69 6e 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_AveMaria_ST_2147767139_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/AveMaria.ST!!AveMaria.ST"
        threat_id = "2147767139"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "AveMaria"
        severity = "Critical"
        info = "AveMaria: an internal category used to refer to some threats"
        info = "ST: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ellocnak.xml" ascii //weight: 1
        $x_1_2 = "Elevation:Administrator!new" ascii //weight: 1
        $x_1_3 = {48 65 79 20 49 27 6d 20 41 64 6d 69 6e 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_AveMaria_ST_2147767139_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/AveMaria.ST!!AveMaria.ST"
        threat_id = "2147767139"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "AveMaria"
        severity = "Critical"
        info = "AveMaria: an internal category used to refer to some threats"
        info = "ST: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Ave_Maria Stealer" ascii //weight: 2
        $x_1_2 = "wmic process call create" ascii //weight: 1
        $x_1_3 = "powershell Add-MpPreference -ExclusionPath " ascii //weight: 1
        $x_1_4 = "select signon_realm, origin_url, username_value, password_value from wow_logins" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

