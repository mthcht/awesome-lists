rule Trojan_Win32_Kazuar_C_2147902703_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kazuar.C!dha"
        threat_id = "2147902703"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kazuar"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 45 1c 0f af 45 14 89 c2 8b 45 18 01 d0 89 45 1c 8b 55 08 8b 45 ?? 01 d0 0f b6 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Kazuar_C_2147902703_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kazuar.C!dha"
        threat_id = "2147902703"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kazuar"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {55 89 e5 83 ec ?? c6 45 ?? 31 c6 45 ?? c0 c6 45 ?? c2 c6 45 ?? 14 c6 45 ?? 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Kazuar_D_2147902704_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kazuar.D!dha"
        threat_id = "2147902704"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kazuar"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 45 f0 8b 00 69 d0 0d 66 19 00 8b 45 f0 89 10 8b 45 f0 8b 00 8d 90 5f f3 6e 3c 8b 45 f0 89 10 8b 45 f4 05 ?? ?? ?? ?? 0f b6 10 8b 45 f4 83 e0 03 0f b6 44 05 eb 31 c2 8b 45 f4 05 ?? ?? ?? ?? 88 10 83 45 f4 01 81 7d f4}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Kazuar_L_2147950857_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kazuar.L!dha"
        threat_id = "2147950857"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kazuar"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "https://fjsconsultoria.com" wide //weight: 1
        $x_1_2 = "https://hauptschule-schwalbenstrasse.de" wide //weight: 1
        $x_1_3 = "https://ingas.rs/wp-includes" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Kazuar_M_2147950859_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kazuar.M!dha"
        threat_id = "2147950859"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kazuar"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "https://empty/ews/Exchange.asmx" wide //weight: 1
        $x_1_2 = "Failed to load '{0}' setting due to {1}" wide //weight: 1
        $x_1_3 = "C:\\ProgramData\\inp\\test" wide //weight: 1
        $x_1_4 = "wss://127.0.0.1:20089/Test" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

