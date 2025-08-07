rule Trojan_Win32_SchExec_HA_2147939824_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SchExec.HA!MTB"
        threat_id = "2147939824"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SchExec"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {2f 00 63 00 72 00 65 00 61 00 74 00 65 00 20 00 2f 00 74 00 6e 00 [0-4] 75 00 70 00 64 00 61 00 74 00 65 00 73 00 5c 00 [0-32] 20 00 2f 00 78 00 6d 00 6c 00 [0-4] 63 00 3a 00 5c 00 75 00 73 00 65 00 72 00 73 00 5c 00 [0-32] 5c 00 61 00 70 00 70 00 64 00 61 00 74 00 61 00 5c 00 6c 00 6f 00 63 00 61 00 6c 00 5c 00 74 00 65 00 6d 00 70 00 5c 00 74 00 6d 00 70 00 [0-8] 2e 00 74 00 6d 00 70 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SchExec_HC_2147940741_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SchExec.HC!MTB"
        threat_id = "2147940741"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SchExec"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {2f 00 63 00 72 00 65 00 61 00 74 00 65 00 20 00 2f 00 74 00 6e 00 20 00 [0-24] 20 00 2f 00 74 00 72 00 20 00 [0-2] 6d 00 73 00 68 00 74 00 61 00 20 00 63 00 3a 00 5c 00 75 00 73 00 65 00 72 00 73 00 5c 00 [0-32] 5c 00 61 00 70 00 70 00 64 00 61 00 74 00 61 00 5c 00 6c 00 6f 00 63 00 61 00 6c 00 5c 00 74 00 65 00 6d 00 70 00 5c 00 [0-24] 2e 00 68 00 74 00 61 00 [0-2] 20 00 2f 00 73 00 63 00 20 00 6d 00 69 00 6e 00 75 00 74 00 65 00 20 00 2f 00 6d 00 6f 00 20 00 [0-4] 20 00 2f 00 72 00 75 00 20 00 [0-2] 02 [0-2] 20 00 2f 00 66 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SchExec_HD_2147941744_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SchExec.HD!MTB"
        threat_id = "2147941744"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SchExec"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {73 00 63 00 68 00 74 00 61 00 73 00 6b 00 73 00 20 00 2f 00 63 00 72 00 65 00 61 00 74 00 65 00 [0-64] 2f 00 74 00 6e 00 20 00 [0-64] 20 00 2f 00 74 00 72 00 20 00 [0-4] 63 00 3a 00 5c 00 75 00 73 00 65 00 72 00 73 00 5c 00 [0-48] 5c 00 61 00 70 00 70 00 64 00 61 00 74 00 61 00 5c 00 72 00 6f 00 61 00 6d 00 69 00 6e 00 67 00 5c 00 23 26 26 06 61 2d 7a 30 2d 39 2e 00 65 00 78 00 65 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SchExec_HI_2147947996_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SchExec.HI!MTB"
        threat_id = "2147947996"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SchExec"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 00 61 00 75 00 33 00 20 00 2f 00 73 00 63 00 20 00 6d 00 69 00 6e 00 75 00 74 00 65 00 20 00 2f 00 6d 00 6f 00 20 00 [0-4] 20 00 2f 00 66 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SchExec_HJ_2147947997_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SchExec.HJ!MTB"
        threat_id = "2147947997"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SchExec"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/create" wide //weight: 1
        $x_5_2 = " svchost " wide //weight: 5
        $x_10_3 = "/tr c:\\programdata" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SchExec_HK_2147948697_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SchExec.HK!MTB"
        threat_id = "2147948697"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SchExec"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "certutil -addstore -f root " wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

