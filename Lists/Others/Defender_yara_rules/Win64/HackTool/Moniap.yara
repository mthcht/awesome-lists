rule HackTool_Win64_Moniap_A_2147718070_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/Moniap.A"
        threat_id = "2147718070"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Moniap"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "-tshack %d %s%s" ascii //weight: 1
        $x_1_2 = "HUC Packet & Socks5 Transmit Tool" ascii //weight: 1
        $x_1_3 = "TCP Port MultiScanner v" ascii //weight: 1
        $x_1_4 = "Remote Registry Configuration" ascii //weight: 1
        $x_1_5 = "Usage: Remarks string" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Win64_Moniap_B_2147718071_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/Moniap.B"
        threat_id = "2147718071"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Moniap"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {74 73 62 2e 6d 73 63 [0-32] 25 73 20 2d 62 69 6e 64 65 72 20 22 25 73 22 [0-16] 25 73 5c 2a 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_2 = {75 73 62 2e 6d 73 63 [0-8] 25 73 2e 64 65 6c [0-16] 44 69 72 65 63 74 58 2e 6d 73 63 [0-16] 75 63 70 2e 6d 73 63}  //weight: 1, accuracy: Low
        $x_1_3 = {2d 74 73 68 61 63 6b 20 25 64 20 25 73 25 73 [0-8] 4d 53 41 53 47 75 69 2e 65 78 65 [0-16] 50 72 6f 67 72 61 6d 44 61 74 61 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 53 74 61 72 74 20 4d 65 6e 75 5c 50 72 6f 67 72 61 6d 73 5c 53 74 61 72 74 75 70 5c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

