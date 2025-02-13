rule Backdoor_Win32_Kelihos_B_2147790312_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Kelihos.B"
        threat_id = "2147790312"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Kelihos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {66 69 6e 64 5f 61 6e 64 5f 6b 69 6c 6c 5f 6f 6c 64 5f 63 6c 69 65 6e 74 73 00}  //weight: 3, accuracy: High
        $x_2_2 = {4d 49 49 42 43 41 4b 43 41 51 45 41 (74 46 2b 63 65 72 46 37 51 4c|78 61 4c 74 33 4e 6f 32 68 45)}  //weight: 2, accuracy: Low
        $x_1_3 = {47 6f 6f 67 6c 65 49 6d 70 6c 00}  //weight: 1, accuracy: High
        $x_1_4 = "smartindex" ascii //weight: 1
        $x_1_5 = {49 44 32 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Kelihos_F_2147790337_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Kelihos.F"
        threat_id = "2147790337"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Kelihos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "[PROXY_SOCKET_WORKER]" ascii //weight: 10
        $x_1_2 = "find_and_kill_old_clients" ascii //weight: 1
        $x_1_3 = "\\Bitcoin\\wallet.dat" ascii //weight: 1
        $x_10_4 = "MIIBCAKCAQEA" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_1_*))) or
            ((1 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Kelihos_A_2147790379_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Kelihos.A"
        threat_id = "2147790379"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Kelihos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "ew2IYHhXV/3AJwsPWNVskg==" ascii //weight: 3
        $x_1_2 = "): failed to anilize reply" ascii //weight: 1
        $x_1_3 = "Failed to write autorun entry" ascii //weight: 1
        $x_1_4 = "presnose not filled" ascii //weight: 1
        $x_1_5 = "smartindex" ascii //weight: 1
        $x_1_6 = "/loggs99" wide //weight: 1
        $x_1_7 = {64 65 63 72 3a 20 00 2e 68 74 6d 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Kelihos_A_2147792442_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Kelihos.gen!A"
        threat_id = "2147792442"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Kelihos"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "[PROXY_SOCKET_WORKER" ascii //weight: 5
        $x_5_2 = "[NET_SERVER_WORKER" ascii //weight: 5
        $x_3_3 = "crush_detected_host" ascii //weight: 3
        $x_3_4 = "Compromzed REG key:" ascii //weight: 3
        $x_3_5 = "m_dictioanries_configs_ids" ascii //weight: 3
        $x_3_6 = "\\wcx_ftp.ini" ascii //weight: 3
        $x_3_7 = "\\SavedDialogHistory\\FTPHost" ascii //weight: 3
        $x_3_8 = "encryptedPassword FROM moz_logins" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_3_*))) or
            ((1 of ($x_5_*) and 3 of ($x_3_*))) or
            ((2 of ($x_5_*) and 1 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Kelihos_A_2147792480_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Kelihos.gen!A!!Kelihos.gen!A"
        threat_id = "2147792480"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Kelihos"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        info = "Kelihos: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "[PROXY_SOCKET_WORKER" ascii //weight: 5
        $x_5_2 = "[NET_SERVER_WORKER" ascii //weight: 5
        $x_3_3 = "crush_detected_host" ascii //weight: 3
        $x_3_4 = "Compromzed REG key:" ascii //weight: 3
        $x_3_5 = "m_dictioanries_configs_ids" ascii //weight: 3
        $x_3_6 = "\\wcx_ftp.ini" ascii //weight: 3
        $x_3_7 = "\\SavedDialogHistory\\FTPHost" ascii //weight: 3
        $x_3_8 = "encryptedPassword FROM moz_logins" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_3_*))) or
            ((1 of ($x_5_*) and 3 of ($x_3_*))) or
            ((2 of ($x_5_*) and 1 of ($x_3_*))) or
            (all of ($x*))
        )
}

