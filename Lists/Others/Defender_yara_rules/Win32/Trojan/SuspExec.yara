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

