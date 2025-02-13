rule Trojan_Win32_Tofumanics_A_2147637829_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tofumanics.A"
        threat_id = "2147637829"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tofumanics"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Common Files\\UniCam SoftWare" ascii //weight: 1
        $x_1_2 = "reg add \"hkey_local_machine\\software\\microsoft\\windows nt\\currentversion\\winlogon \" /v shell /t reg_sz /d \"Explorer.exe," ascii //weight: 1
        $x_1_3 = "Software\\WebMoney\\path" ascii //weight: 1
        $x_1_4 = {72 65 66 75 73 65 2e 74 78 74 00 [0-10] 74 69 6d 69 6e 67 2e 74 78 74 00}  //weight: 1, accuracy: Low
        $x_1_5 = {4d 41 4c 57 41 52 45 00 [0-16] 45 53 53 45 4e 54 49 41 4c 53 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_Tofumanics_B_2147638762_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tofumanics.B"
        threat_id = "2147638762"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tofumanics"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Software\\WebMoney\\Path" ascii //weight: 1
        $x_1_2 = "SYSTEM\\CurrentControlSet\\Control\\Network\\{4D36E972-E325-11CE-BFC1-08002BE10318}" ascii //weight: 1
        $x_1_3 = "reg add \"hkey_local_machine\\software\\microsoft\\windows nt\\currentversion\\winlogon" ascii //weight: 1
        $x_1_4 = {6e 65 74 73 68 20 69 6e 74 65 72 66 61 63 65 20 69 70 20 61 64 64 20 64 6e 73 20 6e 61 6d 65 3d 22 [0-16] 22 20 61 64 64 72 3d [0-16] 69 6e 64 65 78 3d 32 [0-16] 65 72 61 73 65 20 22}  //weight: 1, accuracy: Low
        $x_1_5 = {67 6f 74 6f 20 30 [0-16] 65 72 61 73 65 20 22 [0-16] 72 65 61 64 6d 65 2e 74 78 74 22}  //weight: 1, accuracy: Low
        $x_1_6 = {6c 6f 74 75 73 5c [0-16] 3a 5c 70 72 6f 67 72 61 6d 20 66 69 6c 65 73 5c 6e 6f 74 65 73 5c [0-16] 3a 5c 70 72 6f 67 72 61 6d 20 66 69 6c 65 73 5c 69 62 6d 5c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_Win32_Tofumanics_C_2147645149_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tofumanics.C"
        threat_id = "2147645149"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tofumanics"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "reg add \"hkey_local_machine\\software\\microsoft\\windows nt\\currentversion\\winlogon" ascii //weight: 1
        $x_1_2 = {6c 6f 74 75 73 5c [0-16] 3a 5c 70 72 6f 67 72 61 6d 20 66 69 6c 65 73 5c 6e 6f 74 65 73 5c [0-16] 3a 5c 70 72 6f 67 72 61 6d 20 66 69 6c 65 73 5c 69 62 6d 5c}  //weight: 1, accuracy: Low
        $x_1_3 = {67 65 74 5f 64 6f 77 6e 6c 6f 61 64 5f 69 6e 66 6f 2e 70 68 70 3f 69 64 [0-16] 26 66 6f 72 6d 61 74 3d}  //weight: 1, accuracy: Low
        $x_1_4 = {72 65 61 64 6d 65 2e 74 78 74 [0-16] 2f 63 20 63 6f 70 79 20 2f 79 20 22}  //weight: 1, accuracy: Low
        $x_1_5 = "netsh firewall set opmode disable" ascii //weight: 1
        $x_1_6 = "gateway_result=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_Win32_Tofumanics_D_2147646067_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tofumanics.D"
        threat_id = "2147646067"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tofumanics"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {67 6f 74 6f 20 30 [0-16] 65 72 61 73 65 20 22 [0-16] 72 65 61 64 6d 65 2e 74 78 74 22}  //weight: 1, accuracy: Low
        $x_1_2 = {79 65 73 2e 74 78 74 [0-7] 2f 63 20 63 6d 64 20 2f 63 20 73 68 75 74 64 6f 77 6e 20 2d 72 20 2d 74 20 30}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 08 ff 51 08 b8 60 ea 00 00 e8}  //weight: 1, accuracy: High
        $x_1_4 = "/c erase \"C:\\WINDOWS\\system32\\drivers\\etc\\hosts" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

