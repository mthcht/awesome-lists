rule Trojan_Win32_Dialer_MA_2147836830_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dialer.MA!MTB"
        threat_id = "2147836830"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dialer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {50 64 89 25 00 00 00 00 83 ec 38 53 56 57 89 65 e8 83 65 fc 00 c7 45 e4 01 00 00 00 8b 35 e0 10 40 00 ff d6}  //weight: 5, accuracy: High
        $x_5_2 = {55 54 5d 81 ec b0 01 00 00 53 56 57 6a 24 59 2b c0 8d bd 5c ff ff ff c7 85 58 ff ff ff 94 00 00 00 f3 ab 8d 85 58 ff ff ff 50 ff 15}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Dialer_ADER_2147846135_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dialer.ADER!MTB"
        threat_id = "2147846135"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dialer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 c0 8a 0c 30 80 f1 0a 88 0c 30 40 3d 4e 02 00 00 72}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dialer_A_2147850681_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dialer.A!MTB"
        threat_id = "2147850681"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dialer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b c2 03 c0 8d 44 c1 ?? 8b 1e 89 18 89 06 42 83 fa}  //weight: 2, accuracy: Low
        $x_2_2 = "thindialer" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dialer_SG_2147910970_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dialer.SG!MTB"
        threat_id = "2147910970"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dialer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\newdialer.exe" ascii //weight: 1
        $x_1_2 = "Software\\TrinityFLA" ascii //weight: 1
        $x_1_3 = "\\unsizzle.bat" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dialer_SGA_2147910971_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dialer.SGA!MTB"
        threat_id = "2147910971"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dialer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Program Files\\Dialers" ascii //weight: 1
        $x_1_2 = "DisableCallWaiting" ascii //weight: 1
        $x_1_3 = "RasDialA" ascii //weight: 1
        $x_1_4 = "GTools32 - InstallMIME" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dialer_SGB_2147910972_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dialer.SGB!MTB"
        threat_id = "2147910972"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dialer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/jump.php3" ascii //weight: 1
        $x_1_2 = "ugh spa" ascii //weight: 1
        $x_1_3 = "tsr_media" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

