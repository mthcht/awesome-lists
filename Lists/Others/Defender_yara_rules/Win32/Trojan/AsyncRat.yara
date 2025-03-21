rule Trojan_Win32_AsyncRat_PA_2147753638_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AsyncRat.PA!MTB"
        threat_id = "2147753638"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Z3JhYmJlcl9zbmFwc2hvdA" wide //weight: 1
        $x_1_2 = "Ym90S2lsbGVy" wide //weight: 1
        $x_1_3 = "a2V5TG9nZ2Vy" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AsyncRat_MA_2147816622_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AsyncRat.MA!MTB"
        threat_id = "2147816622"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {d2 7f 14 a7 2b cb e4 46 bf 9c 22 d7 55 22 0e df}  //weight: 10, accuracy: High
        $x_10_2 = {94 ca c5 e4 95 b9 a1 40 9a c2 32 36 1a 7d 96 0f 01}  //weight: 10, accuracy: High
        $x_10_3 = {82 8c 30 ab 9c ca 96 93 19 b6 34 10 a4 89 6c 44 a1 3e fb 30 ad a4 ad af}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_AsyncRat_MA_2147816622_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AsyncRat.MA!MTB"
        threat_id = "2147816622"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {c4 01 ed f7 db 4a 8e 52 a5 5a 0c 34 13 21}  //weight: 5, accuracy: High
        $x_5_2 = {32 2d 41 39 46 43 44 6d 49 67 73 45 66 70 79 63 00 41 31 7d 23}  //weight: 5, accuracy: High
        $x_1_3 = "chkLoadTipsAtStartup" ascii //weight: 1
        $x_1_4 = "Muiucuruousuoufutu" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AsyncRat_MA_2147816622_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AsyncRat.MA!MTB"
        threat_id = "2147816622"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {4f 81 cf 00 ff ff ff 47 0f b6 84 3c d8 02 00 00 88 84 34 d8 02 00 00 88 8c 3c d8 02 00 00 0f b6 84 34 d8 02 00 00 8b 4c 24 14 03 c2 0f b6 c0 0f b6 84 04 d8 02 00 00 30 04 0b 43 3b 5c 24 10 72}  //weight: 10, accuracy: High
        $x_1_2 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_3 = "CreateToolhelp32Snapshot" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AsyncRat_RPX_2147841717_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AsyncRat.RPX!MTB"
        threat_id = "2147841717"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ba bf c0 f6 2a 30 10 40 49 0f 85 f6 ff ff ff e9 04 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AsyncRat_RPX_2147841717_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AsyncRat.RPX!MTB"
        threat_id = "2147841717"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 40 68 00 10 00 00 ff 74 24 10 6a 00 ff 15 ?? ?? ?? ?? 8b f0 85 f6 74 21 ff 74 24 08 ff 74 24 10 56 e8 1f 12 00 00 83 c4 0c ff d6 68 00 80 00 00 6a 00 56 ff 15 ?? ?? ?? ?? ff 74 24 0c e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AsyncRat_RPX_2147841717_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AsyncRat.RPX!MTB"
        threat_id = "2147841717"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 40 68 00 10 00 00 2b f3 56 6a 00 ff 15 ?? ?? ?? ?? 8b f8 85 ff}  //weight: 1, accuracy: Low
        $x_1_2 = "134.122.133.49" ascii //weight: 1
        $x_1_3 = "Client.bin" ascii //weight: 1
        $x_1_4 = "Garbage1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AsyncRat_RPX_2147841717_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AsyncRat.RPX!MTB"
        threat_id = "2147841717"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "aHR0cHM6Ly9wYXN0ZS5mby9yYXcvMGExNWYyZDhkNGM1" ascii //weight: 10
        $x_1_2 = "WaitForSingleObject" ascii //weight: 1
        $x_1_3 = "CryptStringToBinaryA" ascii //weight: 1
        $x_1_4 = "VirtualAlloc" ascii //weight: 1
        $x_1_5 = "CreateThread" ascii //weight: 1
        $x_1_6 = "GetTempPathA" ascii //weight: 1
        $x_1_7 = "Sleep" ascii //weight: 1
        $x_1_8 = "URLDownloadToFileA" ascii //weight: 1
        $x_1_9 = "ftell" ascii //weight: 1
        $x_1_10 = "fseek" ascii //weight: 1
        $x_1_11 = "fopen_s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AsyncRat_RPZ_2147852302_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AsyncRat.RPZ!MTB"
        threat_id = "2147852302"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff d6 ff b5 98 fb ff ff ff d6 0f 57 c0 c7 85 ec fb ff ff 00 00 00 00 8d 95 c0 fb ff ff 66 0f d6 85 e4 fb ff ff 8d 8d e4 fb ff ff e8 ?? ?? ?? ?? c6 45 fc 04 8b 85 e8 fb ff ff 2b 85 e4 fb ff ff 6a 40 68 00 10 00 00 50 6a 00 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AsyncRat_RPZ_2147852302_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AsyncRat.RPZ!MTB"
        threat_id = "2147852302"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 fc 8b f0 ff d6 8d 45 f8 50 8b 45 f8 50 53 8b 45 fc 50 e8 ?? ?? ?? ?? 33 c0 5a 59 59 64 89 10}  //weight: 1, accuracy: Low
        $x_1_2 = "myqcloud.com" wide //weight: 1
        $x_1_3 = "Client.bin" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AsyncRat_CCIC_2147909158_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AsyncRat.CCIC!MTB"
        threat_id = "2147909158"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DLLCALL ( I307CGWG ( 688 + -581 ) & I307CGWG ( 722 + -621 )" ascii //weight: 1
        $x_1_2 = "STRINGREPLACE ( $U30U9FMZ5D , \"6F23F1C78097C1DD086A190344" ascii //weight: 1
        $x_1_3 = "STRINGREPLACE ( \"Chr($Q31373938kcyYM5y)6F23F1C78097C1DD086A190344\" , \"6F23F1C78097C1DD086A190344" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AsyncRat_ASA_2147931668_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AsyncRat.ASA!MTB"
        threat_id = "2147931668"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 57 83 c4 04 81 f3 10 0e 01 00 81 f3 0d 27 00 00 81 eb 58 52 00 00 5b 56 81 ce ea 17 00 00 5e 52 52 83 c4 04 81 ea e0 4e 01 00 81 ca 45 db 00 00 5a 51 81 c9 f8 99 00 00 81 e9 e4 5e 00 00 59 52 83 ec 14 e8 ?? ?? ?? ?? 00 37 32 50 43 45 46 3a 48 37 32 83 c4 18 81 c2 fc}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AsyncRat_Z_2147936647_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AsyncRat.Z!MTB"
        threat_id = "2147936647"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "schtasks /create /f /sc onlogon /rl highest /tn" ascii //weight: 1
        $x_1_2 = "Stub.exe" ascii //weight: 1
        $x_1_3 = "get_ActivatePong" ascii //weight: 1
        $x_1_4 = "vmware" ascii //weight: 1
        $x_1_5 = "nuR\\noisreVtnerruC\\swodniW\\tfosorciM\\erawtfoS" ascii //weight: 1
        $x_1_6 = "get_SslClient" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AsyncRat_Z_2147936647_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AsyncRat.Z!MTB"
        threat_id = "2147936647"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "schtasks /create /f /sc onlogon /rl highest /tn" ascii //weight: 1
        $x_1_2 = "nuR\\noisreVtnerruC\\swodniW\\tfosorciM\\erawtfoS" ascii //weight: 1
        $x_1_3 = "get_SslClient" ascii //weight: 1
        $x_1_4 = "Select * from AntivirusProduct" ascii //weight: 1
        $x_1_5 = "get_TcpClient" ascii //weight: 1
        $x_1_6 = "get_SendSync" ascii //weight: 1
        $x_1_7 = "set_UseShellExecute" ascii //weight: 1
        $x_1_8 = "timeout" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

