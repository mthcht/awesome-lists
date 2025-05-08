rule Trojan_Win32_RemcosRAT_RPC_2147795763_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RemcosRAT.RPC!MTB"
        threat_id = "2147795763"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RemcosRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 c0 8b 4d ec 8a 14 0d ?? ?? ?? ?? 88 55 eb 8b 4d ec 0f b6 75 eb 30 00 [0-32] c7 45 ec 00 00 00 00 c7 45 ec 00 00 00 00 81 7d ec ?? ?? 00 00 0f 83}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 45 ec 83 c0 01 89 45 ec e9 ?? ?? ?? ?? 8d 05 ?? ?? ?? ?? 31 c9 89 04 24 c7 44 24 04 00 00 00 00 89 4d e4 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RemcosRAT_RPE_2147798310_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RemcosRAT.RPE!MTB"
        threat_id = "2147798310"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RemcosRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 31 00 30 00 37 00 2e 00 31 00 38 00 39 00 2e 00 34 00 2e 00 37 00 30 00 2f 00 [0-16] 2e 00 62 00 69 00 6e 00}  //weight: 1, accuracy: Low
        $x_1_2 = "CreateInstance" ascii //weight: 1
        $x_1_3 = "Activator" ascii //weight: 1
        $x_1_4 = "ShellIcon" ascii //weight: 1
        $x_1_5 = "GetExportedTypes" ascii //weight: 1
        $x_1_6 = "TreeItem" ascii //weight: 1
        $x_1_7 = "HttpWebResponse" ascii //weight: 1
        $x_1_8 = "GetResponse" ascii //weight: 1
        $x_1_9 = "MemoryStream" ascii //weight: 1
        $x_1_10 = "HttpWebRequest" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RemcosRAT_RPQ_2147817732_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RemcosRAT.RPQ!MTB"
        threat_id = "2147817732"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RemcosRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {32 f8 03 c0 8b d0 0f b7 f0 35 1b 01 00 00 f7 c2 00 01 00 00 0f b7 c8 8b c6 0f 44 c8 d0 eb 0f b7 c1 75 d8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RemcosRAT_RPF_2147825427_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RemcosRAT.RPF!MTB"
        threat_id = "2147825427"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RemcosRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 40 3c 99 03 04 24 13 54 24 04 83 c4 08 89 07 49 89 c2 6a 01 68 00 20 00 00 8b 07 8b 40 50 50 6a 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RemcosRAT_SPQ_2147837553_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RemcosRAT.SPQ!MTB"
        threat_id = "2147837553"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RemcosRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 4d fc 0f b6 8c 0d e8 fe ff ff 03 4d f8 8b 45 fc 33 d2 f7 75 0c 8b 45 08 0f b6 14 10 03 ca 8b c1 33 d2 f7 75 f0 89 55 f8 8b 45 fc 8a 8c 05 e8 fe ff ff 88 4d f7 8b 55 fc 8b 45 f8 8a 8c 05 e8 fe ff ff 88 8c 15 e8 fe ff ff 8b 55 f8 8a 45 f7 88 84 15 e8 fe ff ff 33 c9 75 ce}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RemcosRAT_A_2147840694_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RemcosRAT.A!MTB"
        threat_id = "2147840694"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RemcosRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "40"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "net.webclient" wide //weight: 10
        $x_10_2 = "[system.reflection.assembly]::load($" wide //weight: 10
        $x_10_3 = ".invoke($" wide //weight: 10
        $x_10_4 = "http" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RemcosRAT_A_2147840694_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RemcosRAT.A!MTB"
        threat_id = "2147840694"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RemcosRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "hdrlavih8" ascii //weight: 2
        $x_2_2 = "strlstrh8" ascii //weight: 2
        $x_2_3 = "vidsRLE" ascii //weight: 2
        $x_2_4 = "VaL_d1PY" ascii //weight: 2
        $x_2_5 = "cmd /c cmd < Preferences.vsd & ping -n 5 localhost" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RemcosRAT_B_2147891219_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RemcosRAT.B!MTB"
        threat_id = "2147891219"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RemcosRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {81 7d f8 05 ?? 00 00 0f 83 ?? 00 00 00 8b 4d f8 8a 94 0d ec ?? ff ff 88 55 ff 0f b6 45 ff}  //weight: 2, accuracy: Low
        $x_2_2 = {88 45 ff 0f b6 4d ff}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RemcosRAT_NRS_2147893377_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RemcosRAT.NRS!MTB"
        threat_id = "2147893377"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RemcosRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {e8 c0 87 ff ff 0f b6 75 ?? 8b 45 f8 8a 4d ?? 84 4c 30 19 75 1b 33 d2 39 55 10 74 0e 8b 45 f4 8b 00 0f b7 04 70}  //weight: 5, accuracy: Low
        $x_1_2 = "%homedrive%\\eegv" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RemcosRAT_NRR_2147893378_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RemcosRAT.NRR!MTB"
        threat_id = "2147893378"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RemcosRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {d3 a5 57 5a 03 90 bc 9f bf c9 e1 96 22 48 12 c7 80 b3 f8 fb 9d 8a c7 81 f3 78 89 69 ed 88 60 ca 30 6b bd 00 ce b4 aa ea 91 1b ff}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RemcosRAT_NA_2147893669_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RemcosRAT.NA!MTB"
        threat_id = "2147893669"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RemcosRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {e8 a5 d5 01 00 83 c4 ?? 3d ?? ?? ?? ?? 0f 83 ?? ?? ?? ?? 89 c1 83 f8 ?? 77 07 88 4e ?? 89 f7 eb 26 89 cb 83 cb 0f 43 53 89 cf e8}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RemcosRAT_NCA_2147896539_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RemcosRAT.NCA!MTB"
        threat_id = "2147896539"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RemcosRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {77 39 6a 09 e8 94 be ff ff 59 c7 45 fc ?? ?? ?? ?? 8b c6 c1 e8 04 50 e8 a0 e7 ff ff 59 89 45 e0}  //weight: 2, accuracy: Low
        $x_2_2 = {a1 30 e3 46 00 85 c0 74 22 8b 0d ?? ?? ?? ?? 56 8d 71 fc 3b f0 72 13 8b 06 85 c0 74 02 ff d0}  //weight: 2, accuracy: Low
        $x_1_3 = "Electrum.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RemcosRAT_NRM_2147897040_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RemcosRAT.NRM!MTB"
        threat_id = "2147897040"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RemcosRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {50 8b 03 8b 00 e8 63 f4 ff ff 50 e8 55 b3 ff ff 8b c8 8b d4 8b c6 e8 b2 e4 ff ff eb 0a 8b c6 8b 53 ?? e8 ae e5 ff ff}  //weight: 5, accuracy: Low
        $x_1_2 = "*Ghz Canyon Shakira Margin Frontier Gossip" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RemcosRAT_Z_2147929925_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RemcosRAT.Z!MTB"
        threat_id = "2147929925"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RemcosRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Remcos" ascii //weight: 1
        $x_1_2 = "%02i:%02i:%02i" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RemcosRAT_Z_2147929925_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RemcosRAT.Z!MTB"
        threat_id = "2147929925"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RemcosRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Downloaded file" ascii //weight: 1
        $x_1_2 = "GetDirectListeningPort" ascii //weight: 1
        $x_1_3 = "Uploaded file" ascii //weight: 1
        $x_1_4 = "reg.exe ADD HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" ascii //weight: 1
        $x_1_5 = "CreateObject(" ascii //weight: 1
        $x_1_6 = "User Data\\Default\\Cookies" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RemcosRAT_Z_2147929925_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RemcosRAT.Z!MTB"
        threat_id = "2147929925"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RemcosRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Remcos" ascii //weight: 1
        $x_1_2 = "CreateObject(\"WScript.Shell\").Run \"cmd" ascii //weight: 1
        $x_1_3 = "\\sysinfo.txt" ascii //weight: 1
        $x_1_4 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion" ascii //weight: 1
        $x_1_5 = "reg.exe ADD HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" ascii //weight: 1
        $x_1_6 = "%02i:%02i:%02i" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RemcosRAT_ZA_2147929926_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RemcosRAT.ZA!MTB"
        threat_id = "2147929926"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RemcosRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Remcos v" ascii //weight: 1
        $x_1_2 = "%02i:%02i:%02i" ascii //weight: 1
        $x_1_3 = "Remcos Agent initialized" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RemcosRAT_ZB_2147932429_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RemcosRAT.ZB!MTB"
        threat_id = "2147932429"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RemcosRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data" ascii //weight: 1
        $x_1_2 = "\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Cookies" ascii //weight: 1
        $x_1_3 = "AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\" ascii //weight: 1
        $x_1_4 = "\\logins.json" ascii //weight: 1
        $x_1_5 = "\\key3.db" ascii //weight: 1
        $x_1_6 = "Agent initialized" ascii //weight: 1
        $x_1_7 = "Access Level:" ascii //weight: 1
        $x_1_8 = "Administrator" ascii //weight: 1
        $x_1_9 = "StartForward" ascii //weight: 1
        $x_1_10 = "StartReverse" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RemcosRAT_BSA_2147940933_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RemcosRAT.BSA!MTB"
        threat_id = "2147940933"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RemcosRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_12_1 = {61 00 73 00 73 00 75 00 72 00 65 00 72 00 20 00 67 00 65 00 6e 00 73 00 74 00 61 00 72 00 74 00 65 00 64 00 65 00 73}  //weight: 12, accuracy: High
        $x_8_2 = {73 00 69 00 66 00 74 00 65 00 72 00 20 00 73 00 6b 00 61 00 6b 00 6b 00 65 00 72 00 6e 00 65 00 73}  //weight: 8, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

