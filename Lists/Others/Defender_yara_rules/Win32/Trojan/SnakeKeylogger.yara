rule Trojan_Win32_SnakeKeylogger_VX_2147793434_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SnakeKeylogger.VX!MTB"
        threat_id = "2147793434"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 a8 8b 4d bc 8b 55 ac 83 7d c4 00 0f 95 c3 80 f3 ff 80 e3 01 0f b6 f3 89 34 24 89 54 24 04 89 4c 24 08 89 44 24 0c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SnakeKeylogger_AB_2147796807_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SnakeKeylogger.AB!MTB"
        threat_id = "2147796807"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 a0 99 b9 03 00 00 00 f7 f9 8b 85 18 f8 ff ff 0f be 0c 10 8b 55 a0 0f b6 44 15 a4 33 c1 8b 4d a0 88 44 0d a4 eb c9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SnakeKeylogger_RPY_2147845778_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SnakeKeylogger.RPY!MTB"
        threat_id = "2147845778"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f6 d0 04 52 34 7f 2a c1 f6 d0 04 5e f6 d0 32 c1 c0 c0 02 f6 d8 88 81 ?? ?? ?? ?? 41 81 f9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SnakeKeylogger_SML_2147926923_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SnakeKeylogger.SML!MTB"
        threat_id = "2147926923"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "aortographic" ascii //weight: 1
        $x_1_2 = "floriken" ascii //weight: 1
        $x_1_3 = "biliousnesses.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SnakeKeylogger_SML_2147926923_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SnakeKeylogger.SML!MTB"
        threat_id = "2147926923"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "irascent forlagslederen" ascii //weight: 1
        $x_1_2 = "applicrcr cervicothoracic parameterlisternes" ascii //weight: 1
        $x_1_3 = "paradichlorbenzol krydseres.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SnakeKeylogger_Z_2147929760_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SnakeKeylogger.Z!MTB"
        threat_id = "2147929760"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SnakeKeylogger" ascii //weight: 1
        $x_1_2 = "sendMessage?chat_id=" ascii //weight: 1
        $x_1_3 = "sendDocument?chat_id" ascii //weight: 1
        $x_1_4 = "Screenshot" ascii //weight: 1
        $x_1_5 = "Keystrokes" ascii //weight: 1
        $x_1_6 = "api.telegram.org" ascii //weight: 1
        $x_1_7 = "software\\microsoft\\windows\\currentversion\\run" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SnakeKeylogger_ZA_2147938093_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SnakeKeylogger.ZA!MTB"
        threat_id = "2147938093"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "get_encryptedPassword" ascii //weight: 1
        $x_1_2 = "get_encryptedUsername" ascii //weight: 1
        $x_1_3 = "get_timePasswordChanged" ascii //weight: 1
        $x_1_4 = "get_passwordField" ascii //weight: 1
        $x_1_5 = "get_logins" ascii //weight: 1
        $x_1_6 = "KeyLoggerEventArgsEventHandler" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SnakeKeylogger_RVA_2147944856_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SnakeKeylogger.RVA!MTB"
        threat_id = "2147944856"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {28 00 20 00 22 00 43 00 68 00 72 00 22 00 20 00 2c 00 20 00 24 00 [0-20] 20 00 28 00 20 00 22 00 42 00 69 00 74 00 58 00 4f 00 52 00 22 00 20 00 2c 00 20 00 24 00 [0-20] 20 00 2c 00 20 00 24 00 [0-20] 20 00 29 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_2 = {28 20 22 43 68 72 22 20 2c 20 24 [0-20] 20 28 20 22 42 69 74 58 4f 52 22 20 2c 20 24 [0-20] 20 2c 20 24 [0-20] 20 29 20 29}  //weight: 1, accuracy: Low
        $x_1_3 = {28 00 20 00 22 00 4d 00 6f 00 64 00 22 00 20 00 2c 00 20 00 24 00 [0-20] 20 00 2b 00 20 00 31 00 33 00 20 00 2c 00 20 00 32 00 35 00 36 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_4 = {28 20 22 4d 6f 64 22 20 2c 20 24 [0-20] 20 2b 20 31 33 20 2c 20 32 35 36 20 29}  //weight: 1, accuracy: Low
        $x_1_5 = {46 00 49 00 4c 00 45 00 49 00 4e 00 53 00 54 00 41 00 4c 00 4c 00 20 00 28 00 20 00 22 00 [0-24] 22 00 20 00 2c 00 20 00 40 00 54 00 45 00 4d 00 50 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 00 22 00 20 00 2c 00 20 00 31 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_6 = {46 49 4c 45 49 4e 53 54 41 4c 4c 20 28 20 22 [0-24] 22 20 2c 20 40 54 45 4d 50 44 49 52 20 26 20 22 5c 00 22 20 2c 20 31 20 29}  //weight: 1, accuracy: Low
        $x_1_7 = {47 00 4c 00 4f 00 42 00 41 00 4c 00 20 00 24 00 [0-20] 20 00 3d 00 20 00 24 00 [0-20] 20 00 28 00 20 00 [0-20] 20 00 28 00 20 00 22 00 78 00 25 00 3a 00 30 00 [0-24] 22 00 20 00 29 00 20 00 2c 00 20 00 02 20 00 28 00 20 00 22 00 5e 00 30 00 22 00 22 00 06 00 2b 00 22 00 20 00 29 00 20 00 26 00 20 00 42 00 49 00 4e 00 41 00 52 00 59 00 4c 00 45 00 4e 00 20 00 28 00 20 00 24 00 [0-20] 20 00 29 00 20 00 26 00 20 00 02 20 00 28 00 20 00 22 00 61 00 22 00 20 00 29 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_8 = {47 4c 4f 42 41 4c 20 24 [0-20] 20 3d 20 24 [0-20] 20 28 20 [0-20] 20 28 20 22 78 25 3a 30 [0-24] 22 20 29 20 2c 20 02 20 28 20 22 5e 30 22 22 06 2b 22 20 29 20 26 20 42 49 4e 41 52 59 4c 45 4e 20 28 20 24 [0-20] 20 29 20 26 20 02 20 28 20 22 61 22 20 29 20 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

