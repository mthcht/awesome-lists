rule Trojan_Win32_SuspIex_B_2147980381_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspIex.B!MTB"
        threat_id = "2147980381"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspIex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "irm '0x" wide //weight: 1
        $x_1_2 = "| iex" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SuspIex_A_2147980382_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspIex.A!MTB"
        threat_id = "2147980382"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspIex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {69 00 72 00 6d 00 20 00 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 [0-6] 2e 00 [0-6] 2e 00 [0-6] 2e 00 [0-6] 7c 00 69 00 65 00 78 00}  //weight: 1, accuracy: Low
        $x_1_2 = {69 00 72 00 6d 00 20 00 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 [0-6] 2e 00 [0-6] 2e 00 [0-6] 2e 00 [0-6] 20 00 7c 00 20 00 69 00 65 00 78 00}  //weight: 1, accuracy: Low
        $x_1_3 = {69 00 72 00 6d 00 20 00 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 [0-6] 2e 00 [0-6] 2e 00 [0-6] 2e 00 [0-6] 7c 00 20 00 69 00 65 00 78 00}  //weight: 1, accuracy: Low
        $x_1_4 = {69 00 72 00 6d 00 20 00 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 [0-6] 2e 00 [0-6] 2e 00 [0-6] 2e 00 [0-6] 2f 00 [0-32] 7c 00 20 00 69 00 65 00 78 00}  //weight: 1, accuracy: Low
        $x_1_5 = {69 00 72 00 6d 00 20 00 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 [0-6] 2e 00 [0-6] 2e 00 [0-6] 2e 00 [0-6] 2f 00 [0-32] 7c 00 69 00 65 00 78 00}  //weight: 1, accuracy: Low
        $x_1_6 = {69 00 72 00 6d 00 20 00 27 00 [0-6] 2e 00 [0-6] 2e 00 [0-6] 2e 00 [0-6] 2f 00 [0-32] 27 00 7c 00 69 00 65 00 78 00}  //weight: 1, accuracy: Low
        $n_50_7 = "127." wide //weight: -50
        $n_50_8 = "localhost" wide //weight: -50
        $n_50_9 = "0.0.0.0" wide //weight: -50
        $n_50_10 = "10." wide //weight: -50
        $n_50_11 = "192.168." wide //weight: -50
        $n_50_12 = "169.254." wide //weight: -50
        $n_10_13 = "Final result" wide //weight: -10
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (1 of ($x*))
}

rule Trojan_Win32_SuspIex_C_2147980385_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspIex.C!MTB"
        threat_id = "2147980385"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspIex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "irm 'http" wide //weight: 1
        $x_1_2 = "'|iex" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

