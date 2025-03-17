rule TrojanDownloader_Win32_Doina_GSH_2147809630_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Doina.GSH!MTB"
        threat_id = "2147809630"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Doina"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://FileApi.gyaott.top/001/puppet.Txt" ascii //weight: 1
        $x_1_2 = "HttpOpenRequest" ascii //weight: 1
        $x_1_3 = "HttpSendRequest" ascii //weight: 1
        $x_1_4 = "VirtualProtect" ascii //weight: 1
        $x_1_5 = "VirtualAlloc" ascii //weight: 1
        $x_1_6 = "HTTP/1.1" ascii //weight: 1
        $x_1_7 = "HTTP/1.0" ascii //weight: 1
        $x_1_8 = "Accept-Language: zh-cn" ascii //weight: 1
        $x_1_9 = "@https://" ascii //weight: 1
        $x_1_10 = "ilLe4oxilLe4oxilLe4ox" ascii //weight: 1
        $x_1_11 = "3oDOW3oDOWbNYbF77d38" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Doina_GZT_2147813312_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Doina.GZT!MTB"
        threat_id = "2147813312"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Doina"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b d1 57 8b 7c 24 ?? 33 c0 c1 e9 ?? f3 ab 8b ca 83 e1 ?? f3 aa 5f c3}  //weight: 10, accuracy: Low
        $x_1_2 = "FileApi.gyaott.top" ascii //weight: 1
        $x_1_3 = "VirtualProtect" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Doina_D_2147816521_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Doina.D!MTB"
        threat_id = "2147816521"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Doina"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {c6 84 24 51 02 00 00 72 88 9c 24 ?? ?? ?? ?? c6 84 24 ?? ?? ?? ?? 61 c6 84 24 ?? ?? ?? ?? 74 88 9c 24 ?? ?? ?? ?? c6 84 24 ?? ?? ?? ?? 44 c6 84 24 ?? ?? ?? ?? 69 c6 84 24 ?? ?? ?? ?? 72 88 9c 24 ?? ?? ?? ?? c6 84 24 ?? ?? ?? ?? 63 c6 84 24 ?? ?? ?? ?? 74 c6 84 24 ?? ?? ?? ?? 6f c6 84 24 ?? ?? ?? ?? 72 c6 84 24 ?? ?? ?? ?? 79 c6 84 24}  //weight: 10, accuracy: Low
        $x_1_2 = "KillTimer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Doina_ARA_2147912985_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Doina.ARA!MTB"
        threat_id = "2147912985"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Doina"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8a 03 30 e0 88 03 43 e2 f7}  //weight: 2, accuracy: High
        $x_2_2 = "Global\\UR147GWms" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Doina_ARAZ_2147936193_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Doina.ARAZ!MTB"
        threat_id = "2147936193"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Doina"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {0f b6 d0 8a 92 08 30 40 00 32 91 1b 30 40 00 fe c0 88 54 0d b0 41 3c 13 76 02 32 c0 4e 75 e1}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

