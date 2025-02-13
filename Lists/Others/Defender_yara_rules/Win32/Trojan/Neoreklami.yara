rule Trojan_Win32_Neoreklami_RF_2147847148_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreklami.RF!MTB"
        threat_id = "2147847148"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreklami"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ctfikw jele pcwagx jfu nktpxc ujq pgxshkxt mqeutlqb got gxrlylt" ascii //weight: 1
        $x_1_2 = "pwwy wtsjmrx dga ujlpv qxkxoucn wqbc ivmcc" ascii //weight: 1
        $x_1_3 = "npb xvca xgbvcgetl skwkqawi" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreklami_RE_2147847149_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreklami.RE!MTB"
        threat_id = "2147847149"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreklami"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {99 89 84 24 ?? ?? 00 00 89 94 24 ?? ?? 00 00 ff b4 24 ?? ?? 00 00 ff b4 24 ?? ?? 00 00 09 00 00 00 33 84 24 ?? ?? 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {d3 f8 99 89 84 24 ?? ?? 00 00 89 94 24 ?? ?? 00 00 ff b4 24 ?? ?? 00 00 ff b4 24 ?? ?? 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreklami_MBYR_2147915221_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreklami.MBYR!MTB"
        threat_id = "2147915221"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreklami"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {77 77 6f 74 67 4b 48 5a 53 74 74 4f 62 49 7a 00 54 63 49 48 44 42 54 51 68 6c 48 4e 65 50 64 62 65 6a 5a 77 77 71 43 00 66 4e 44 47 4a 4a 59 4a 48 76 58 42 64 71 47 46 79 58 00 00 70 4f 78 61}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreklami_EC_2147922680_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreklami.EC!MTB"
        threat_id = "2147922680"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreklami"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_7_1 = {2b 1e c1 fb 02 8b c3 d1 e8 2b d0 3b d3 73 04 33 db eb 02 03 d8 3b d9 0f 42 d9}  //weight: 7, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreklami_MBWD_2147927705_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreklami.MBWD!MTB"
        threat_id = "2147927705"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreklami"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {e9 5f 61 04 00 af 52 1e 7a 57 cd 73 1e a6 63 36 66 f4 29 4a b9 e9 62 35 13 3a 65 5e b9 09 b5 e1 34 3c 01 2b 4f 8b 90 de b8 e8 28 ea 92 d9 cc}  //weight: 2, accuracy: High
        $x_1_2 = {2c da 16 96 f8 f2 c1 41 16 59 aa ed 88 36 b1 b0 c9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

