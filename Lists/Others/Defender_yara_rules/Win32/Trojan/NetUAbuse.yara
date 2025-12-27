rule Trojan_Win32_NetUAbuse_A_2147907155_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NetUAbuse.A!gpo"
        threat_id = "2147907155"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NetUAbuse"
        severity = "Critical"
        info = "gpo: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {6e 00 65 00 74 00 2e 00 65 00 78 00 65 00 [0-16] 20 00 75 00 73 00 65 00 72 00 20 00}  //weight: 10, accuracy: Low
        $x_1_2 = {6e 00 65 00 74 00 2e 00 65 00 78 00 65 00 [0-16] 20 00 75 00 73 00 65 00 72 00 20 00 61 00 64 00 6d 00 69 00 6e 00 33 00}  //weight: 1, accuracy: Low
        $x_1_3 = " fuckoff123" wide //weight: 1
        $x_1_4 = " clownstrike123" wide //weight: 1
        $x_1_5 = " fuckingcrowd123" wide //weight: 1
        $x_1_6 = " welcomebacktotheoffice123" wide //weight: 1
        $x_1_7 = " adm1nbac p@ssw0ddp@ssw" wide //weight: 1
        $x_1_8 = " whiteninja p@ssw0ddp@ssw" wide //weight: 1
        $x_1_9 = {20 00 61 00 64 00 6d 00 69 00 6e 00 [0-5] 70 00 34 00 24 00 35 00 77 00 30 00 72 00 64 00 31 00 32 00 33 00}  //weight: 1, accuracy: Low
        $x_1_10 = {20 00 64 00 63 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 [0-5] 70 00 40 00 73 00 73 00 77 00 30 00 72 00 64 00 31 00 32 00 33 00 61 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_NetUAbuse_A_2147916317_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NetUAbuse.A"
        threat_id = "2147916317"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NetUAbuse"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {6e 00 65 00 74 00 2e 00 65 00 78 00 65 00 [0-16] 20 00 75 00 73 00 65 00 72 00 20 00}  //weight: 10, accuracy: Low
        $x_1_2 = " fuckoff123" wide //weight: 1
        $x_1_3 = " clownstrike123" wide //weight: 1
        $x_1_4 = " fuckingcrowd123" wide //weight: 1
        $x_1_5 = " welcomebacktotheoffice123" wide //weight: 1
        $x_1_6 = " adm1nbac p@ssw0ddp@ssw" wide //weight: 1
        $x_1_7 = " whiteninja p@ssw0ddp@ssw" wide //weight: 1
        $x_1_8 = {20 00 61 00 64 00 6d 00 69 00 6e 00 [0-5] 70 00 34 00 24 00 35 00 77 00 30 00 72 00 64 00 31 00 32 00 33 00 32 00 31 00}  //weight: 1, accuracy: Low
        $x_1_9 = {61 00 64 00 6d 00 69 00 6e 00 5f 00 67 00 70 00 6f 00 [0-5] 61 00 62 00 63 00 64 00 31 00 32 00 33 00 34 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

