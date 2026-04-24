rule Trojan_Win64_KarstoRAT_A_2147967681_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/KarstoRAT.A!AMTB"
        threat_id = "2147967681"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "KarstoRAT"
        severity = "Critical"
        info = "AMTB: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "/notify?event=log&user=" ascii //weight: 3
        $x_3_2 = "/notify?event=heartbeat&user=" ascii //weight: 3
        $x_2_3 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 2
        $x_2_4 = "/upload-screen" ascii //weight: 2
        $x_2_5 = "/client-upload&filename=" ascii //weight: 2
        $x_2_6 = "/client-download" ascii //weight: 2
        $x_2_7 = "&public_ip=" ascii //weight: 2
        $x_2_8 = "&msg=" ascii //weight: 2
        $x_1_9 = "SecurityNotifier" ascii //weight: 1
        $x_1_10 = "SecurityService" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 5 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 6 of ($x_2_*))) or
            ((2 of ($x_3_*) and 4 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_3_*) and 5 of ($x_2_*))) or
            (all of ($x*))
        )
}

