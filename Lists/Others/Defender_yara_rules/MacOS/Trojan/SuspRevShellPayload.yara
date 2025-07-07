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

