rule Trojan_Win32_Banload_D_2147686130_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Banload.D"
        threat_id = "2147686130"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {37 30 45 42 30 42 33 44 46 43 35 34 46 33 00}  //weight: 1, accuracy: High
        $x_1_2 = "67F237CB0D489E46F6584BE8114C5CF817BE76EE173FE1" ascii //weight: 1
        $x_1_3 = {30 31 30 46 44 37 36 43 39 32 33 34 41 33 00 00 ff ff ff ff 06 00 00 00 44 31 37 37 45 45}  //weight: 1, accuracy: High
        $x_1_4 = {34 36 32 35 30 36 32 31 44 44 37 37 00 00 00 00 55 8b ec 33 c0 55 68}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Banload_E_2147695225_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Banload.E"
        threat_id = "2147695225"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 1c 0e 32 5d 0c 88 19 41 4a 75 f4}  //weight: 1, accuracy: High
        $x_1_2 = {81 38 33 c0 c2 08 74 9b}  //weight: 1, accuracy: High
        $x_1_3 = {8b 10 50 b9 ad de ef be 6a 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Banload_R_2147735718_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Banload.R"
        threat_id = "2147735718"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "type..hash.struct { F uintptr; os/exec.w io.Writer; os/exec.pr *os.File }" ascii //weight: 1
        $x_1_2 = "keypanic: refererrefreshrunningserial:signal" ascii //weight: 1
        $x_1_3 = "\"*chacha20poly1305.chacha20poly1305" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Banload_YQM_2147794522_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Banload.YQM!MTB"
        threat_id = "2147794522"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 74 74 70 3a 2f 2f 73 69 6e 64 61 72 73 70 65 6e 2e 6f 72 67 2e 62 72 2f [0-37] 6c 63 2d 61 72 71 75 69 76 6f 73 2f [0-21] 63 68 [0-3] 72 6d 65 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_2 = "URLDownloadToFile" ascii //weight: 1
        $x_1_3 = "ShellExecuteA" ascii //weight: 1
        $x_1_4 = "GetTempPathA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Banload_MA_2147809799_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Banload.MA!MTB"
        threat_id = "2147809799"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {a2 30 ba 4a 00 b8 69 98 49 00 a3 34 bb 4a 00 a1 c4 90 4a 00 bb 01 00 00 00 c6 44 24 0e 00 c6 44 24 0d 00 c7 44 24 10 01 00 00 00 89 44 24 14 3b c3 0f 8e}  //weight: 1, accuracy: High
        $x_1_2 = "http://176.96.138.103/keybinder" ascii //weight: 1
        $x_1_3 = "Escape" ascii //weight: 1
        $x_1_4 = "CapsLock" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Banload_RPX_2147892875_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Banload.RPX!MTB"
        threat_id = "2147892875"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {83 c0 04 83 c0 14 56 8b f0 8d 7c 24 28 b9 38 00 00 00 f3 a5 5e 6a 40 68 00 30 00 00 8b 5c 24 64 53 6a 00 ff 56 04}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Banload_ARA_2147900674_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Banload.ARA!MTB"
        threat_id = "2147900674"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "://zepetto.online/ao/" ascii //weight: 2
        $x_2_2 = "DLL Injected" ascii //weight: 2
        $x_2_3 = "PROCESS INJECTION" ascii //weight: 2
        $x_2_4 = "C:\\HWID.txt" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Banload_MBFW_2147905877_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Banload.MBFW!MTB"
        threat_id = "2147905877"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {61 72 71 75 69 76 6f 00 44 53 43 32 30 34 30 31 30 00 00 44 53 43 32 30 34 30 31 30}  //weight: 1, accuracy: High
        $x_1_2 = {4c 15 40 00 4c 15 40 00 08 15 40 00 78 00 00 00 80 00 00 00 8a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

