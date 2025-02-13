rule Trojan_Win32_Qadars_A_2147681691_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qadars.A"
        threat_id = "2147681691"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qadars"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {25 73 3f 76 65 72 3d 25 73 26 75 69 64 3d 25 73 26 70 72 6f 63 65 73 73 3d 25 73 26 70 69 64 3d 25 6c 75 26 6c 65 76 65 6c 3d 25 64 26 65 72 72 6f 72 3d 25 6c 75 26 73 74 61 74 75 73 3d 25 6c 75 26 74 69 6d 65 3d 25 6c 75 26 6d 65 73 73 61 67 65 3d 25 6c 75 26 63 6f 75 6e 74 65 72 3d 25 66 26 6c 65 66 74 3d 25 6c 75 26 64 61 74 61 3d 25 73 00}  //weight: 1, accuracy: High
        $x_1_2 = {25 64 20 64 61 79 73 20 25 30 2e 32 64 3a 25 30 2e 32 64 3a 25 30 2e 32 64 00}  //weight: 1, accuracy: High
        $x_1_3 = {47 61 74 65 53 65 6e 64 4f 6e 6c 69 6e 65 00}  //weight: 1, accuracy: High
        $x_1_4 = {00 73 7a 42 6f 74 6e 65 74 4e 61 6d 65 00}  //weight: 1, accuracy: High
        $x_1_5 = {00 73 7a 55 70 64 61 74 65 50 69 70 65 00}  //weight: 1, accuracy: High
        $x_1_6 = {00 62 6f 74 5f 75 70 6c 6f 61 64 5f 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_7 = {ff ff 21 43 65 87 c7 85 ?? ?? ff ff 01 00 00 00 b9 20 00 00 00 8d b5 ?? ?? ff ff 8d bd ?? ?? ff ff f3 a5 6a 00 68 ?? ?? 00 00 04 00 c7 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Qadars_B_2147720873_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qadars.B"
        threat_id = "2147720873"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qadars"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "100"
        strings_accuracy = "High"
    strings:
        $x_100_1 = {d6 d4 9d 6a aa 6e 89 0f 3e 91 37 38 39 5f 5f 4b 45 59 5f 5f}  //weight: 100, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qadars_B_2147720873_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qadars.B"
        threat_id = "2147720873"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qadars"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "100"
        strings_accuracy = "High"
    strings:
        $x_100_1 = {d6 d4 9d 6a aa 6e 89 0f 3e 91 37 38 39 5f 5f 4b 45 59 5f 5f}  //weight: 100, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qadars_C_2147722777_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qadars.C!bit"
        threat_id = "2147722777"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qadars"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "33"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f b6 16 33 d0 81 e2 ?? ?? ?? ?? c1 e8 08 33 04 95 ?? ?? ?? ?? 46 49 75 e7}  //weight: 10, accuracy: Low
        $x_10_2 = "== %ws %ws 0x%p %u" ascii //weight: 10
        $x_10_3 = "GD!brWJJBeTgTGSgEFB/quRcfCkBHWgl" ascii //weight: 10
        $x_1_4 = "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" wide //weight: 1
        $x_1_5 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_6 = "vbox" ascii //weight: 1
        $x_1_7 = "qemu" ascii //weight: 1
        $x_1_8 = "vmware" ascii //weight: 1
        $x_1_9 = "virtual hd" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

