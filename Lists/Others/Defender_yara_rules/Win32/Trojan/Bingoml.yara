rule Trojan_Win32_Bingoml_BBX_2147795455_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bingoml.BBX!MTB"
        threat_id = "2147795455"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bingoml"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {30 01 8d 04 0e 83 e0 0f 0f b6 80 ?? ?? ?? ?? 30 41 01 8d 04 0f 83 e0 0f 0f b6 80 ?? ?? ?? ?? 30 41 02 8d 04 0b 83 e0 0f 8d 49 04 0f b6 80 ?? ?? ?? ?? 30 41 ff 81 fa 00 42 01 00 72 b4}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bingoml_R_2147823105_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bingoml.R!MTB"
        threat_id = "2147823105"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bingoml"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "svmtoolsd.exe" ascii //weight: 1
        $x_1_2 = "C:\\ProgramData\\WinKs" ascii //weight: 1
        $x_1_3 = "windowscer.shop/admin/login.php" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bingoml_HPPO_2147826864_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bingoml.HPPO!MTB"
        threat_id = "2147826864"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bingoml"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "TaftyaFSTfTYXfyuwe" ascii //weight: 1
        $x_1_2 = "haGAStuxt.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bingoml_RA_2147828649_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bingoml.RA!MTB"
        threat_id = "2147828649"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bingoml"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4d fc 8b 55 08 0f b7 0c 4a 8b 45 fc 33 d2 be ?? 00 00 00 f7 f6 83 c2 31 33 ca 8b 55 fc 8b 45 f8 66 89 0c 50}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bingoml_MA_2147834997_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bingoml.MA!MTB"
        threat_id = "2147834997"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bingoml"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {ce b9 27 40 64 91 83 ae cb 0f 73 c2 0e ce 21 a3 42 c3 03 a3 a7 8f 50 62 9d 73 f8 07 ff 05 d4 be 0c e4 dd f7 99 a6 6e 11 01 d0 d2 fa 0e af 23 9a}  //weight: 10, accuracy: High
        $x_10_2 = {30 95 77 b1 d4 3a 6b 88 d1 55 b0 45 49 85 6b a9 3f 6e 98 a0 06 9e 0c 44 f8 0d 6b df b4 6f 95 9d e7 e8 04 27 96 a6 5f 18 55 27 ac 8d 07 e8 d2 5a}  //weight: 10, accuracy: High
        $x_2_3 = "frmForgotPassword" ascii //weight: 2
        $x_2_4 = "taskkill /im " wide //weight: 2
        $x_2_5 = "[ ALTDOWN ]" wide //weight: 2
        $x_2_6 = " [Passwords]" wide //weight: 2
        $x_2_7 = "S  u  r  e" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bingoml_RDA_2147836251_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bingoml.RDA!MTB"
        threat_id = "2147836251"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bingoml"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Global\\3pc6RWOgectGTFqCowxjeGy3XIGPtLwNrsr2zDctYD4hAU5pj4GW7rm8gHrHyTB6" wide //weight: 1
        $x_1_2 = "userprofile" wide //weight: 1
        $x_1_3 = "%temp%\\" wide //weight: 1
        $x_2_4 = {64 a1 30 00 00 00 68 00 00 00 f0 6a 01 6a 00 8b 40 0c 6a 00 68 ?? ?? ?? ?? 8b 40 14 8b 40 20}  //weight: 2, accuracy: Low
        $x_2_5 = {0f b6 04 39 41 33 c6 c1 ee 08 25 ff 00 00 00 33 b4 85 00 fc ff ff 3b ca}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bingoml_GAB_2147898381_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bingoml.GAB!MTB"
        threat_id = "2147898381"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bingoml"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {e5 f0 fc e7 c7 45 ?? a7 ea e7 89 33 c0 80 74 05 ec 89 40 83 f8 0c}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

