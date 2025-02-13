rule Trojan_Win32_SuspMSIExecBeacon_A_2147811772_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspMSIExecBeacon.A!ibt"
        threat_id = "2147811772"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspMSIExecBeacon"
        severity = "Critical"
        info = "ibt: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {73 00 74 00 61 00 72 00 74 00 20 00 6d 00 73 00 69 00 65 00 78 00 65 00 63 00 20 00 2f 00 71 00 2f 00 69 00 [0-5] 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 [0-16] 3a 00 38 00 30 00 38 00 30 00 2f 00}  //weight: 2, accuracy: Low
        $x_2_2 = {73 00 74 00 61 00 72 00 74 00 20 00 6d 00 73 00 69 00 65 00 78 00 65 00 63 00 20 00 2d 00 71 00 2d 00 69 00 [0-5] 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 [0-16] 3a 00 38 00 30 00 38 00 30 00 2f 00}  //weight: 2, accuracy: Low
        $x_2_3 = {73 00 74 00 61 00 72 00 74 00 20 00 6d 00 73 00 69 00 65 00 78 00 65 00 63 00 20 00 2f 00 71 00 2d 00 69 00 [0-5] 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 [0-16] 3a 00 38 00 30 00 38 00 30 00 2f 00}  //weight: 2, accuracy: Low
        $x_2_4 = {73 00 74 00 61 00 72 00 74 00 20 00 6d 00 73 00 69 00 65 00 78 00 65 00 63 00 20 00 2d 00 71 00 2f 00 69 00 [0-5] 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 [0-16] 3a 00 38 00 30 00 38 00 30 00 2f 00}  //weight: 2, accuracy: Low
        $x_1_5 = "start explorer" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

