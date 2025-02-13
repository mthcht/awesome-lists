rule Trojan_Win32_Socgolsh_B_2147851198_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Socgolsh.B"
        threat_id = "2147851198"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Socgolsh"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 81 3c 07 56 69 75 ?? 66 81 7c 07 02 72 74 75 ?? 81 7c 07 09 6c 6f 63 00 75}  //weight: 1, accuracy: Low
        $x_1_2 = {66 81 7c 07 01 69 72 75 ?? 66 81 7c 07 03 74 75 75 ?? 81 7c 07 09 6c 6f 63 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Socgolsh_YAD_2147851673_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Socgolsh.YAD"
        threat_id = "2147851673"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Socgolsh"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {80 7c 07 01 69 75 ?? 66 81 7c 07 03 74 75 75 ?? 81 7c 07 09 6c 6f 63 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Socgolsh_SC_2147909962_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Socgolsh.SC"
        threat_id = "2147909962"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Socgolsh"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "powershell" wide //weight: 1
        $x_1_2 = "wget https://www.python.org/ftp" wide //weight: 1
        $x_1_3 = ".zip;expand-archive -literalpath" wide //weight: 1
        $x_1_4 = {2d 00 64 00 65 00 73 00 74 00 69 00 6e 00 61 00 74 00 69 00 6f 00 6e 00 70 00 61 00 74 00 68 00 [0-255] 5c 00 70 00 79 00 33 00 3b 00 64 00 65 00 6c 00}  //weight: 1, accuracy: Low
        $x_1_5 = {7a 00 69 00 70 00 3b 00 6c 00 73 00 [0-255] 5c 00 70 00 79 00 33 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Socgolsh_SD_2147909963_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Socgolsh.SD"
        threat_id = "2147909963"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Socgolsh"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {73 00 63 00 68 00 74 00 61 00 73 00 6b 00 73 00 20 00 2f 00 63 00 72 00 65 00 61 00 74 00 65 00 [0-48] 22 00 70 00 79 00 70 00 69 00 2d 00 70 00 79 00 22 00}  //weight: 1, accuracy: Low
        $x_1_2 = "schtasks /run /tn \"pypi-py\"" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Socgolsh_SE_2147909964_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Socgolsh.SE"
        threat_id = "2147909964"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Socgolsh"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "101"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "python.exe" wide //weight: 1
        $x_1_2 = "pythonw.exe" wide //weight: 1
        $x_1_3 = "taskhostw.exe" wide //weight: 1
        $x_100_4 = {2e 00 70 00 79 00 20 00 [0-255] 20 00 2d 00 69 00 70 00 20 00 [0-255] 20 00 2d 00 70 00 6f 00 72 00 74 00 20 00}  //weight: 100, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Socgolsh_SF_2147916063_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Socgolsh.SF"
        threat_id = "2147916063"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Socgolsh"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "32"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "powershell" wide //weight: 1
        $x_10_2 = {77 00 67 00 65 00 74 00 20 00 68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 77 00 77 00 77 00 2e 00 70 00 79 00 74 00 68 00 6f 00 6e 00 2e 00 6f 00 72 00 67 00 2f 00 66 00 74 00 70 00 [0-255] 2e 00 7a 00 69 00 70 00 20 00 2d 00 6f 00 75 00 74 00 66 00 69 00 6c 00 65 00 20 00}  //weight: 10, accuracy: Low
        $x_1_3 = ".zip;ls" wide //weight: 1
        $x_10_4 = ".zip;expand-archive -literalpath" wide //weight: 10
        $x_10_5 = {7a 00 69 00 70 00 [0-16] 2d 00 64 00 65 00 73 00 74 00 69 00 6e 00 61 00 74 00 69 00 6f 00 6e 00 70 00 61 00 74 00 68 00}  //weight: 10, accuracy: Low
        $x_1_6 = " https://bootstrap.pypa.io/get-pip.py" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Socgolsh_SG_2147916318_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Socgolsh.SG"
        threat_id = "2147916318"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Socgolsh"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "schtasks /create /f /tn" wide //weight: 1
        $x_1_2 = {5c 00 70 00 79 00 74 00 68 00 6f 00 6e 00 77 00 2e 00 65 00 78 00 65 00 [0-255] 2e 00 70 00 79 00 20 00 2d 00 69 00 70 00 [0-255] 2d 00 70 00 6f 00 72 00 74 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Socgolsh_SI_2147919880_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Socgolsh.SI"
        threat_id = "2147919880"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Socgolsh"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "powershell" wide //weight: 1
        $x_1_2 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 77 00 77 00 77 00 2e 00 70 00 79 00 74 00 68 00 6f 00 6e 00 2e 00 6f 00 72 00 67 00 2f 00 66 00 74 00 70 00 [0-255] 2e 00 7a 00 69 00 70 00 20 00}  //weight: 1, accuracy: Low
        $x_1_3 = "-literalpath" wide //weight: 1
        $x_1_4 = "-destinationpath" wide //weight: 1
        $x_1_5 = " https://bootstrap.pypa.io/" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

