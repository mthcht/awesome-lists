rule Trojan_Win32_Vapsup_C_2147612236_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vapsup.C"
        threat_id = "2147612236"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vapsup"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {83 e8 00 74 43 83 e8 01 74 2c 83 e8 02 75 71 ff d6}  //weight: 5, accuracy: High
        $x_1_2 = "f83d6fdb-c872-4bcf-ac08-4e61d55446c5" wide //weight: 1
        $x_1_3 = "http://www.kaolabao.net/bo/update.ini" wide //weight: 1
        $x_1_4 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_5 = "toolSn.jsp" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Vapsup_E_2147617748_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vapsup.E"
        threat_id = "2147617748"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vapsup"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4d c4 83 c1 01 89 4d c4 8b 55 c4 3b 55 cc 73 31 8b 45 0c 50 e8 89 fd ff ff 83 c4 04 66 89 45 c0 0f b7 4d c0 81 f1 ?? ?? 00 00 51 8d 4d d0 e8 1f 01 00 00 8b 55 f0 8b 45 0c 8d 0c 50 89 4d 0c eb be}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 55 f4 8b 45 08 0f b7 0c 50 83 f9 41 7c ?? 8b 55 f4 8b 45 08 0f b7 0c 50 83 f9 46 7f ?? 8b 55 f4 8b 45 08 0f b7 0c 50 83 e9 37 66 89 4d f0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vapsup_G_2147617918_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vapsup.G"
        threat_id = "2147617918"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vapsup"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "-LIBGCCW32-EH-2-SJLJ-GTHR-MINGW32" ascii //weight: 10
        $x_1_2 = {8b 45 0c 89 04 24 e8 ?? ?? ff ff [0-4] 0f b7 [0-2] 35 ?? ?? 00 00 [0-3] 89 44 24 04 8b 4d 08 89 0c 24 c7 45 ?? ?? 00 00 00 e8 ?? ?? ?? 00 8b 45}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 4d 0c 89 0c 24 e8 ?? ?? ff ff [0-3] 0f b7 c0 35 ?? ?? 00 00 89 45 98 8b 02 8b 40 f4 89 45 94 8b 55 94 b8 fe ff ff 1f 29 d0 83 f8 01 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

