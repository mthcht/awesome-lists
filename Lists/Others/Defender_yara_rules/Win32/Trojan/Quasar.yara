rule Trojan_Win32_Quasar_A_2147756659_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Quasar.A!MTB"
        threat_id = "2147756659"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Quasar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "start mailto:fredisoft@bol.com.br" wide //weight: 1
        $x_1_2 = "cmd.exe /c powershell Add-MpPreference -ExclusionPath C:\\Users" wide //weight: 1
        $x_1_3 = "kicmhdjog" ascii //weight: 1
        $x_1_4 = "nomcomp" ascii //weight: 1
        $x_1_5 = "fmzftplfkfdgufjhswaiabwmucbvlvo" ascii //weight: 1
        $x_1_6 = "omhrmiotl" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Quasar_RT_2147811332_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Quasar.RT!MTB"
        threat_id = "2147811332"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Quasar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "jantokemitko1" ascii //weight: 1
        $x_1_2 = "T0FRNHMXFFYKLLMXIIXKXI" ascii //weight: 1
        $x_1_3 = "ShoparaGrizli01" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Quasar_RPC_2147836243_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Quasar.RPC!MTB"
        threat_id = "2147836243"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Quasar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$browser_folders" ascii //weight: 1
        $x_1_2 = "System.Net.WebClient" ascii //weight: 1
        $x_1_3 = "USERNAME.zip" ascii //weight: 1
        $x_1_4 = "api.telegram.org/bot5651243701" ascii //weight: 1
        $x_1_5 = "garrettdetectors.sk" ascii //weight: 1
        $x_1_6 = "APPDATA\\ot.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Quasar_RPE_2147838112_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Quasar.RPE!MTB"
        threat_id = "2147838112"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Quasar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "fajka.xyz/Roblox_generator.exe" wide //weight: 1
        $x_1_2 = "discord.gg/c8GhRpbkFr" wide //weight: 1
        $x_1_3 = "DownloadFile" ascii //weight: 1
        $x_1_4 = "Opacity" ascii //weight: 1
        $x_1_5 = "Delay" ascii //weight: 1
        $x_1_6 = "FFLoader" wide //weight: 1
        $x_1_7 = "rat\\rat" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Quasar_MA_2147838838_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Quasar.MA!MTB"
        threat_id = "2147838838"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Quasar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {cd 0a 0e 97 1f 9a 76 af f4 f0 4d eb 25 c4 1e a5 3d 9c cc 56 0c 46 e5 90 d6 7b 0f 6e 50 30 75 da}  //weight: 5, accuracy: High
        $x_5_2 = {f9 b8 d0 90 b5 5d 90 a5 32 b2 c5 b7 76 10 67 0f 30 10 b1 af 9b 0f ea cb 4f 08 6a 4f b4 f4 51 f2}  //weight: 5, accuracy: High
        $x_5_3 = {03 fd b6 90 9e 11 b7 01 6f 1e dd b6 40 08 4a 36 b4 76 a6 e6 4a fb f7 e5 97 9f f2 5f 05 2e 96 72}  //weight: 5, accuracy: High
        $x_1_4 = "InitCommonControls" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Quasar_NHQ_2147848981_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Quasar.NHQ!MTB"
        threat_id = "2147848981"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Quasar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {c1 e6 02 89 74 24 ?? e8 7b 35 05 00 8b 44 24 ?? 8b 44 24 ?? 0f b6 5c 24 ?? 8b 6c 24 ?? 8b b5 08 01 00 00 8b 95 0c 01 00 00}  //weight: 5, accuracy: Low
        $x_1_2 = "nnEDu" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Quasar_MX_2147927896_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Quasar.MX!MTB"
        threat_id = "2147927896"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Quasar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {06 07 02 07 91 03 07 03 6f 20 00 00 0a 5d 6f 21 00 00 0a 61 d2 9c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

