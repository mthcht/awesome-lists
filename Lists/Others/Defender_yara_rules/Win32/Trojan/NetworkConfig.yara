rule Trojan_Win32_NetworkConfig_A_2147766428_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NetworkConfig.A"
        threat_id = "2147766428"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NetworkConfig"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6e 00 62 00 74 00 73 00 74 00 61 00 74 00 [0-16] 2d 00 6e 00}  //weight: 1, accuracy: Low
        $x_1_2 = {6e 00 6c 00 74 00 65 00 73 00 74 00 [0-16] 2f 00 64 00 63 00}  //weight: 1, accuracy: Low
        $x_1_3 = {6e 00 65 00 74 00 73 00 74 00 61 00 74 00 [0-16] 2d 00 6e 00}  //weight: 1, accuracy: Low
        $x_1_4 = {6e 00 65 00 74 00 73 00 74 00 61 00 74 00 [0-16] 2d 00 73 00}  //weight: 1, accuracy: Low
        $x_1_5 = {72 00 6f 00 75 00 74 00 65 00 [0-16] 70 00 72 00 69 00 6e 00 74 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_NetworkConfig_C_2147766430_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NetworkConfig.C!pwsh"
        threat_id = "2147766430"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NetworkConfig"
        severity = "Critical"
        info = "pwsh: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {77 00 69 00 6e 00 33 00 32 00 5f 00 6e 00 65 00 74 00 77 00 6f 00 72 00 6b 00 61 00 64 00 61 00 70 00 74 00 65 00 72 00 63 00 6f 00 6e 00 66 00 69 00 67 00 75 00 72 00 61 00 74 00 69 00 6f 00 6e 00 [0-64] 2d 00 63 00 6f 00 6d 00 70 00 75 00 74 00 65 00 72 00 6e 00 61 00 6d 00 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NetworkConfig_B_2147768111_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NetworkConfig.B!netsh"
        threat_id = "2147768111"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NetworkConfig"
        severity = "Critical"
        info = "netsh: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6e 00 65 00 74 00 73 00 68 00 [0-32] 73 00 65 00 74 00 20 00}  //weight: 1, accuracy: Low
        $x_1_2 = {6e 00 65 00 74 00 73 00 68 00 [0-32] 61 00 64 00 64 00}  //weight: 1, accuracy: Low
        $x_1_3 = {6e 00 65 00 74 00 73 00 68 00 [0-32] 64 00 65 00 6c 00 65 00 74 00 65 00}  //weight: 1, accuracy: Low
        $x_1_4 = {6e 00 65 00 74 00 73 00 68 00 [0-32] 64 00 75 00 6d 00 70 00}  //weight: 1, accuracy: Low
        $x_1_5 = {6e 00 65 00 74 00 73 00 68 00 [0-4] 2d 00 66 00}  //weight: 1, accuracy: Low
        $x_1_6 = {6e 00 65 00 74 00 73 00 68 00 [0-4] 64 00 69 00 61 00 67 00 20 00 73 00 68 00 6f 00 77 00}  //weight: 1, accuracy: Low
        $x_1_7 = {6e 00 65 00 74 00 73 00 68 00 [0-4] 77 00 6c 00 61 00 6e 00 20 00 73 00 68 00 6f 00 77 00}  //weight: 1, accuracy: Low
        $n_5_8 = "\\filter.exe" wide //weight: -5
        $n_5_9 = "thor\\signatures" wide //weight: -5
        $n_5_10 = ".yms-textfilter" wide //weight: -5
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (1 of ($x*))
}

rule Trojan_Win32_NetworkConfig_E_2147770145_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NetworkConfig.E"
        threat_id = "2147770145"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NetworkConfig"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {69 00 70 00 63 00 6f 00 6e 00 66 00 69 00 67 00 [0-16] 2f 00 61 00 6c 00 6c 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

