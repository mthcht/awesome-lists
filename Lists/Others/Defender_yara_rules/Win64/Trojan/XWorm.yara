rule Trojan_Win64_XWorm_GPA_2147904521_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/XWorm.GPA!MTB"
        threat_id = "2147904521"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "XWorm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "src\\main.rshttps://107.175.3.10" ascii //weight: 5
        $x_5_2 = ".binhttps://github.comInternet" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_XWorm_DA_2147922667_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/XWorm.DA!MTB"
        threat_id = "2147922667"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "XWorm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:/explorerwin/mewobfm.dll" ascii //weight: 1
        $x_1_2 = "Failed to load the DLL" ascii //weight: 1
        $x_10_3 = "C:/explorerwi/explorer.exe" ascii //weight: 10
        $x_1_4 = "C:/explorerwin/python.exe" ascii //weight: 1
        $x_12_5 = "C:/explorerwi/pdf.dll" ascii //weight: 12
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_1_*))) or
            ((1 of ($x_12_*) and 1 of ($x_1_*))) or
            ((1 of ($x_12_*) and 1 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_XWorm_AXM_2147926498_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/XWorm.AXM!MTB"
        threat_id = "2147926498"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "XWorm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "taskkill /IM EpicGamesLauncher.exe /F" ascii //weight: 2
        $x_2_2 = "taskkill /IM FortniteClient-Win64-Shipping_BE.exe /F" ascii //weight: 2
        $x_2_3 = "taskkill /IM FortniteClient-Win64-Shipping.exe /F" ascii //weight: 2
        $x_2_4 = "taskkill /IM x64dbg.exe" ascii //weight: 2
        $x_3_5 = "net stop winmgmt" ascii //weight: 3
        $x_4_6 = "ipconfig /flushdnetsh winsock renetsh advfirewalnetsh int ipv4 rnetsh int ipv6 ripconfig /releasnetsh int ip res" ascii //weight: 4
        $x_5_7 = "Permanent Spoofer\\x64\\Release\\Permanent Spoofer.pdb" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_XWorm_PAFW_2147926653_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/XWorm.PAFW!MTB"
        threat_id = "2147926653"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "XWorm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {66 0f 72 e1 04 66 0f 6f c1 66 0f 72 d0 1f 66 0f fe c1 66 0f 38 40 c5 66 0f fa d0 66 0f 6e c2 0f 54 d6 66 0f 67 d2 66 0f 67 d2 66 0f fc d0 66 0f 6e 41 f8 0f 57 d0 66 0f 7e 51 f8 41 83 f8 28 0f 8c}  //weight: 2, accuracy: High
        $x_2_2 = {41 f7 e8 c1 fa 04 8b c2 c1 e8 1f 03 d0 0f be c2 6b c8 36 41 0f b6 c0 41 ff c0 2a c1 04 35 41 30 41 ff 41 83 f8 2c 7c}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_XWorm_GVA_2147935573_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/XWorm.GVA!MTB"
        threat_id = "2147935573"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "XWorm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b 55 10 48 8b 45 f0 48 01 d0 0f b6 00 0f be d0 8b 45 fc 01 c2 8b 45 fc c1 e0 0a 01 c2 8b 45 fc c1 e8 06 31 d0 89 45 fc 48 83 45 f0 01 48 8b 45 10 48 89 c1 ?? ?? ?? ?? ?? 48 39 45 f0 72 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_XWorm_SDEL_2147940094_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/XWorm.SDEL!MTB"
        threat_id = "2147940094"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "XWorm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {31 c9 31 d2 45 31 c9 ff 15 fb 55 ff ff 48 8b 0d fc b0 ff ff 4c 63 59 04 8b 0d ce a3 ff ff 8b 15 cc a3 ff ff 8d 69 ff 0f af e9 89 e9}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

