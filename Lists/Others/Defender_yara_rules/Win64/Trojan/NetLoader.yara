rule Trojan_Win64_NetLoader_NLA_2147898763_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/NetLoader.NLA!MTB"
        threat_id = "2147898763"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "NetLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {89 5d f4 89 55 fc 74 52 48 83 0d 6a 0c 02 00 ?? 41 83 c8 04 25 ?? ?? ?? ?? 44 89 05 3a 31 02 00 3d ?? ?? ?? ?? 74 28 3d 60 06 02 00 74 21}  //weight: 5, accuracy: Low
        $x_1_2 = "WIN72K8R2" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_NetLoader_DA_2147904752_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/NetLoader.DA!MTB"
        threat_id = "2147904752"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "NetLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_10_2 = "4382.bimmobil.xyz" wide //weight: 10
        $x_1_3 = {2f 00 70 00 6c 00 61 00 79 00 2f 00 [0-15] 2e 00 70 00 68 00 70 00}  //weight: 1, accuracy: Low
        $x_1_4 = "URLDownloadToFileA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_NetLoader_ARAX_2147954583_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/NetLoader.ARAX!MTB"
        threat_id = "2147954583"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "NetLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "://github.com/fkubitc/windows-update/raw/refs/heads/main/" wide //weight: 3
        $x_2_2 = "DisableAntiSpyware" wide //weight: 2
        $x_2_3 = "gpupdate /force" wide //weight: 2
        $x_2_4 = "\\Windows\\CurrentVersion\\Run" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_NetLoader_MK_2147959470_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/NetLoader.MK!MTB"
        threat_id = "2147959470"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "NetLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "35"
        strings_accuracy = "High"
    strings:
        $x_25_1 = {c7 45 20 68 00 00 00 0f 57 c0 0f 11 45 28 0f 11 45 38 0f 11 45 48 0f 11 45 58 0f 11 45 68 0f 11 45 78 48 8b 4b 10 48 b8 ff ff ff ff ff ff ff 7f 48 2b c1 48 83 f8 01}  //weight: 25, accuracy: High
        $x_4_2 = "PingClient/1.0" ascii //weight: 4
        $x_3_3 = "downloaded_file_" ascii //weight: 3
        $x_1_4 = "AUTH_SUCCESS" ascii //weight: 1
        $x_1_5 = "file_url" ascii //weight: 1
        $x_1_6 = "C:\\Info" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

