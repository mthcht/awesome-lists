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

