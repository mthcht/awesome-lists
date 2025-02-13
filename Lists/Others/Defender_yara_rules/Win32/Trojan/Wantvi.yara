rule Trojan_Win32_Wantvi_A_114036_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Wantvi.A!dll"
        threat_id = "114036"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Wantvi"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 e8 14 ff ff ff 8b 4c 24 1c 50 68 ?? ?? 00 00 51 68 ?? ?? 00 10 56 ff 15 ?? ?? 00 10 83 c4 18 68 00 28 00 00 6a 08 ff d5 50 ff d7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Wantvi_D_116205_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Wantvi.D"
        threat_id = "116205"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Wantvi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "26"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "\\SystemRoot\\murka.dat" wide //weight: 10
        $x_10_2 = "\\SystemRoot\\medichi.exe" wide //weight: 10
        $x_2_3 = "\\SystemRoot\\medichi2.exe" wide //weight: 2
        $x_2_4 = "\\Registry\\Machine\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 2
        $x_1_5 = "ZwTerminateProcess" ascii //weight: 1
        $x_1_6 = "ZwOpenProcess" ascii //weight: 1
        $x_1_7 = "HalMakeBeep" ascii //weight: 1
        $x_1_8 = "\\avp.exe" ascii //weight: 1
        $x_1_9 = "\\kav.exe" ascii //weight: 1
        $x_1_10 = "\\wincom32.sys" ascii //weight: 1
        $x_1_11 = "\\mpfirewall.sys" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 6 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Wantvi_E_116218_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Wantvi.E"
        threat_id = "116218"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Wantvi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "41"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {55 8b ec 81 ec ?? ?? 00 00 [0-12] 68 04 01 00 00 8d 85 ?? ?? ff ff 50 ff 15 ?? ?? ?? 00 68 ?? ?? ?? 00 8d 8d ?? ?? ff ff 51 ff 15 ?? ?? ?? 00 6a 1b 68 00 ?? ?? 00 68 00 ?? ?? 00 68 00 ?? ?? 00 8d 95 ?? ?? ff ff 52}  //weight: 10, accuracy: Low
        $x_10_2 = {5c 75 73 65 72 [0-1] 33 32 2e 64 61 74}  //weight: 10, accuracy: Low
        $x_10_3 = "GetSystemDirectoryA" ascii //weight: 10
        $x_10_4 = "bljaha muaha zainalo vse!=" ascii //weight: 10
        $x_1_5 = "alo vsea=" ascii //weight: 1
        $x_1_6 = "/6:aja mqaga" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Wantvi_F_116376_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Wantvi.F"
        threat_id = "116376"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Wantvi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8a 06 02 07 88 06 46 4f 49 81 ff ?? ?? ?? 00 75 05 bf ?? ?? ?? 00 83 f9 00 74 02 eb e3 c3}  //weight: 10, accuracy: Low
        $x_10_2 = "SOFTWARE\\Microsoft\\DirectShow\\9c" ascii //weight: 10
        $x_2_3 = {2d d0 07 00 00 ba 00 00 00 00 b9 04 00 00 00 f7 f1 ba 00 00 00 00 b9 a0 05 00 00 f7 e1 03 d8 b8 00 00 00 00}  //weight: 2, accuracy: High
        $x_1_4 = {2d d0 07 00 00 bb 00 00 00 00 ba 00 00 00 00 b9 20 05 08 00 f7 e1 8b d8 b8 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = "CreateMutex" ascii //weight: 1
        $x_1_6 = "CoCreateInstance" ascii //weight: 1
        $x_1_7 = "Sleep" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 4 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Wantvi_I_123790_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Wantvi.I"
        threat_id = "123790"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Wantvi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {f7 75 18 8b 45 14 0f be 14 10 33 ca 8b 45 ?? 03 45 ?? 88 08 eb cb}  //weight: 2, accuracy: Low
        $x_2_2 = {eb 09 8b 45 fc 83 c0 01 89 45 fc 8b 4d fc 3b 4d 0c 7d 0b 8b 55 08 03 55 fc c6 02 00 eb e4}  //weight: 2, accuracy: High
        $x_1_3 = {eb 17 6a 00 6a 06 ff 15 ?? ?? ?? ?? 85 c0 75 04 33 c0 eb 05 b8 01 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

