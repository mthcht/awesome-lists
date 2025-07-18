rule Trojan_MacOS_SuspRevShellPayload_A_2147945646_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/SuspRevShellPayload.A"
        threat_id = "2147945646"
        type = "Trojan"
        platform = "MacOS: "
        family = "SuspRevShellPayload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {30 0c 80 d2 01 fe 46 d3 20 f8 7f d3 e2 03 1f aa e1 66 02 d4 e3 03 20 aa 01 42 80 d2}  //weight: 1, accuracy: High
        $x_1_2 = {e0 f2 e1 83 1f f8 02 01 80 d2 e1 63 22 cb 02 02 80 d2 50 0c 80 d2 e1 66 02 d4 42 fc 42 d3 e0 03 23 aa 42 fc 41 d3 e1 03 02 aa}  //weight: 1, accuracy: High
        $x_1_3 = {50 0b 80 d2 e1 66 02 d4 ea 03 1f aa 5f 01 02 eb 21 ff ff 54 e1 45 8c d2 21 cd ad f2 e1 65 ce f2 01 0d e0 f2 e1 83 1f f8 01 01 80}  //weight: 1, accuracy: High
        $x_1_4 = {d2 e0 63 21 cb e1 03 1f aa e2 03 1f aa 70 07 80 d2 e1 66 02 d4}  //weight: 1, accuracy: High
        $x_1_5 = "_memcpy" ascii //weight: 1
        $x_1_6 = "_mmap" ascii //weight: 1
        $x_1_7 = "_mprotect" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_SuspRevShellPayload_P1_2147946766_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/SuspRevShellPayload.P1"
        threat_id = "2147946766"
        type = "Trojan"
        platform = "MacOS: "
        family = "SuspRevShellPayload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {61 ac 8e d2 81 2d ac f2 81 ee cd f2 41 ce e5 f2 e1 03 1f f8 21 ed 8d d2 c1 6d ae f2 e1 65 c8 f2 21 8c ed f2 e1 83 1e f8 21 08 8e d2 01 8e ad f2 21 6d cc f2 21 8c ee f2}  //weight: 1, accuracy: High
        $x_1_2 = {e1 e5 8d d2 01 ae ac f2 c1 0d c0 f2 e1 03 1d f8 e1 a5 8e d2 61 4e ae f2 e1 45 cc f2 21 cd ed f2}  //weight: 1, accuracy: High
        $x_1_3 = {01 07 80 d2 e1 63 21 cb e1 03 1b f8 e0 03 01 aa e1 43 01 d1 e2 03 1f aa 70 07 80 d2 e1 66 02 d4}  //weight: 1, accuracy: High
        $x_1_4 = "_memcpy" ascii //weight: 1
        $x_1_5 = "_mmap" ascii //weight: 1
        $x_1_6 = "_mprotect" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_SuspRevShellPayload_P2_2147946767_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/SuspRevShellPayload.P2"
        threat_id = "2147946767"
        type = "Trojan"
        platform = "MacOS: "
        family = "SuspRevShellPayload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {30 0c 80 d2 01 fe 46 d3 ?? ?? ?? ?? e2 03 1f aa e1 66 02 d4}  //weight: 1, accuracy: Low
        $x_1_2 = {02 04 80 d2 e1 63 22 cb ?? ?? 80 d2 10 0d 80 d2 e1 66 02 d4 e0 03 23 aa 41 fc 43 d3 50 0d 80 d2 e1 66 02 d4 e0 03 23 aa e1 03 1f aa e2 03 1f aa d0 03 80 d2 e1 66 02 d4}  //weight: 1, accuracy: Low
        $x_1_3 = {02 01 80 d2 e1 63 22 cb ?? ?? 80 d2 10 0d 80 d2 e1 66 02 d4 e0 03 23 aa 41 fc 43 d3 50 0d 80 d2 e1 66 02 d4 e0 03 23 aa e1 03 1f aa e2 03 1f aa d0 03 80 d2 e1 66 02 d4}  //weight: 1, accuracy: Low
        $x_1_4 = {e1 45 8c d2 21 cd ad f2 e1 65 ce f2 01 0d e0 f2 e1 83 1f f8 01 01 80 d2 e0 63 21 cb e1 03 1f aa e2 03 1f aa 70 07 80 d2 e1 66 02 d4}  //weight: 1, accuracy: High
        $x_1_5 = "_memcpy" ascii //weight: 1
        $x_1_6 = "_mmap" ascii //weight: 1
        $x_1_7 = "_mprotect" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

