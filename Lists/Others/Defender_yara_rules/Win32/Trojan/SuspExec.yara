rule Trojan_Win32_SuspExec_YY_2147920411_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspExec.YY"
        threat_id = "2147920411"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspExec"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "cmd.exe" wide //weight: 10
        $x_10_2 = {61 00 75 00 74 00 6f 00 69 00 74 00 33 00 2e 00 65 00 78 00 65 00 20 00 [0-255] 2e 00 61 00 33 00 78 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SuspExec_YX_2147920412_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspExec.YX"
        threat_id = "2147920412"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspExec"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "101"
        strings_accuracy = "Low"
    strings:
        $n_100_1 = " -path " wide //weight: -100
        $x_1_2 = "pythonw.exe" wide //weight: 1
        $x_1_3 = "taskhostw.exe" wide //weight: 1
        $x_100_4 = {20 00 2d 00 69 00 70 00 20 00 [0-255] 20 00 2d 00 70 00 6f 00 72 00 74 00 20 00 34 00 34 00 33 00}  //weight: 100, accuracy: Low
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((1 of ($x_100_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_SuspExec_SB_2147940113_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspExec.SB"
        threat_id = "2147940113"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspExec"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "mshta.exe" wide //weight: 5
        $x_5_2 = "vbscript:execute(" wide //weight: 5
        $x_5_3 = "powershell" wide //weight: 5
        $x_5_4 = "strreverse" wide //weight: 5
        $x_5_5 = "llehS.tpircsW" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_SuspExec_SE_2147940952_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspExec.SE"
        threat_id = "2147940952"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspExec"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "node.exe" wide //weight: 2
        $x_2_2 = "spawn(" wide //weight: 2
        $x_2_3 = "execsync" wide //weight: 2
        $n_100_4 = "msedgewebview2.exe" wide //weight: -100
        $n_1000_5 = "if false == false echo" wide //weight: -1000
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Trojan_Win32_SuspExec_SEA_2147941102_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspExec.SEA"
        threat_id = "2147941102"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspExec"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {72 00 65 00 67 00 [0-48] 61 00 64 00 64 00 [0-48] 72 00 65 00 67 00 5f 00 73 00 7a 00}  //weight: 1, accuracy: Low
        $x_1_2 = {5c 00 61 00 70 00 70 00 64 00 61 00 74 00 61 00 5c 00 72 00 6f 00 61 00 6d 00 69 00 6e 00 67 00 5c 00 6e 00 6f 00 64 00 65 00 [0-48] 6e 00 6f 00 64 00 65 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_3 = {5c 00 61 00 70 00 70 00 64 00 61 00 74 00 61 00 5c 00 72 00 6f 00 61 00 6d 00 69 00 6e 00 67 00 5c 00 6e 00 6f 00 64 00 65 00 [0-255] 2e 00 6c 00 6f 00 67 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SuspExec_HB_2147942785_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspExec.HB!MTB"
        threat_id = "2147942785"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspExec"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "41"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "/c sc create" wide //weight: 1
        $x_5_2 = {62 00 69 00 6e 00 70 00 61 00 74 00 68 00 3d 00 [0-34] 5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 73 00 76 00 63 00 68 00 6f 00 73 00 74 00 2e 00 65 00 78 00 65 00}  //weight: 5, accuracy: Low
        $x_35_3 = {72 00 65 00 67 00 20 00 61 00 64 00 64 00 20 00 68 00 6b 00 6c 00 6d 00 5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 5c 00 63 00 75 00 72 00 72 00 65 00 6e 00 74 00 63 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 73 00 65 00 74 00 5c 00 73 00 65 00 72 00 76 00 69 00 63 00 65 00 73 00 5c 00 [0-20] 5c 00 70 00 61 00 72 00 61 00 6d 00 65 00 74 00 65 00 72 00 73 00 20 00 2f 00 76 00 20 00 73 00 65 00 72 00 76 00 69 00 63 00 65 00 64 00 6c 00 6c 00 20 00 2f 00 74 00 20 00 72 00 65 00 67 00 5f 00 65 00 78 00 70 00 61 00 6e 00 64 00 5f 00 73 00 7a 00 20 00 2f 00 64 00 20 00 [0-22] 5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 [0-20] 2e 00 64 00 61 00 74 00}  //weight: 35, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SuspExec_HC_2147944673_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspExec.HC!MTB"
        threat_id = "2147944673"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspExec"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 00 74 00 6d 00 70 00 20 00 2f 00 45 00 6e 00 66 00 6f 00 72 00 63 00 65 00 64 00 52 00 75 00 6e 00 41 00 73 00 41 00 64 00 6d 00 69 00 6e 00 20 00 2f 00 52 00 75 00 6e 00 41 00 73 00 41 00 64 00 6d 00 69 00 6e 00 20 00 43 00 3a 00 5c 00 55 00 73 00 65 00 72 00 73 00 5c 00 50 00 75 00 62 00 6c 00 69 00 63 00 5c 00 44 00 6f 00 63 00 75 00 6d 00 65 00 6e 00 74 00 73 00 5c 00 [0-16] 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SuspExec_HD_2147944674_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspExec.HD!MTB"
        threat_id = "2147944674"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspExec"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/c choice /C Y /N /D Y /T 3 & Del C:\\Windows\\Microsoft.NET\\Framework\\v" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SuspExec_HF_2147945901_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspExec.HF!MTB"
        threat_id = "2147945901"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspExec"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 00 72 00 61 00 6d 00 65 00 77 00 6f 00 72 00 6b 00 5c 00 76 00 [0-20] 5c 00 72 00 65 00 67 00 73 00 76 00 63 00 73 00 2e 00 65 00 78 00 65 00 [0-6] 3a 00 5c 00}  //weight: 1, accuracy: Low
        $n_100_2 = ".dll" wide //weight: -100
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Trojan_Win32_SuspExec_HI_2147947712_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspExec.HI!MTB"
        threat_id = "2147947712"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspExec"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "51"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "ping localhost -n 1 &" wide //weight: 1
        $x_1_2 = "ping 127.0.0.1 -n 1 &" wide //weight: 1
        $x_50_3 = {26 00 20 00 73 00 74 00 61 00 72 00 74 00 20 00 43 00 3a 00 5c 00 55 00 73 00 65 00 72 00 73 00 5c 00 [0-32] 5c 00 41 00 70 00 70 00 44 00 61 00 74 00 61 00 5c 00 4c 00 6f 00 63 00 61 00 6c 00 5c 00 [0-48] 2e 00 65 00 78 00 65 00}  //weight: 50, accuracy: Low
        $n_300_4 = {41 00 70 00 70 00 44 00 61 00 74 00 61 00 5c 00 4c 00 6f 00 63 00 61 00 6c 00 5c 00 [0-48] 5c 00}  //weight: -300, accuracy: Low
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((1 of ($x_50_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_SuspExec_HJ_2147951578_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspExec.HJ!MTB"
        threat_id = "2147951578"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspExec"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "32"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = "trimend('=')" wide //weight: 20
        $x_10_2 = {2d 00 73 00 68 00 72 00 20 00 24 00 [0-8] 29 00 20 00 2d 00 62 00 61 00 6e 00 64 00 20 00}  //weight: 10, accuracy: Low
        $x_1_3 = ") -bor $" wide //weight: 1
        $x_1_4 = "::gettemppath()" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

