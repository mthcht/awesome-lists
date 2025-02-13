rule Trojan_Win32_VirLock_RPP_2147811676_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VirLock.RPP!MTB"
        threat_id = "2147811676"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VirLock"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 06 90 e9 00 00 00 00 32 c2 90 88 07 90 46 90 47 90 49 90 83 f9 00 90 0f 85 e2 ff ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VirLock_RPP_2147811676_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VirLock.RPP!MTB"
        threat_id = "2147811676"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VirLock"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 06 32 c2 88 07 46 90 47 90 49}  //weight: 1, accuracy: High
        $x_1_2 = {8a 06 32 c2 88 07 46 47 e9 00 00 00 00 49 83 f9 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_VirLock_RPQ_2147811677_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VirLock.RPQ!MTB"
        threat_id = "2147811677"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VirLock"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 06 90 32 c2 90 88 07 90 46 90 47 90 49 90 83 f9 00 90 e9 d2 ff ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VirLock_RPR_2147811678_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VirLock.RPR!MTB"
        threat_id = "2147811678"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VirLock"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 06 32 c2 88 07 46 47 49 83 f9 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VirLock_RPS_2147811898_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VirLock.RPS!MTB"
        threat_id = "2147811898"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VirLock"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {32 c2 90 88 07 90 46 90 47 90 49 90 83 f9 00 90}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VirLock_RPT_2147811899_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VirLock.RPT!MTB"
        threat_id = "2147811899"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VirLock"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 06 32 c2 90 88 07 46 47 49 90 83 f9 00 90 e9 12 00 00 00 8b df 90 b9 80 03 00 00 ba d5 00 00 00 e9 da ff ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VirLock_RPT_2147811899_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VirLock.RPT!MTB"
        threat_id = "2147811899"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VirLock"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {46 47 49 83 f9 00 0f 85 1a 00 00 00 e9 20 00 00 00 81 ec e0 02 00 00 be b8 d0 4a 00 e9 ce ff ff ff ba 02 00 00 00 8a 06 32 c2 88 07 e9 cf ff ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VirLock_RPU_2147811900_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VirLock.RPU!MTB"
        threat_id = "2147811900"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VirLock"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ba 93 00 00 00 8a 06 90 32 c2 90 88 07 90 e9 cf ff ff ff bf 00 40 4b 00 8b df 90 b9 9c 03 00 00 e9 db ff ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VirLock_RPM_2147815369_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VirLock.RPM!MTB"
        threat_id = "2147815369"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VirLock"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {88 07 90 46 90 47 90 49 90 83 f9 00 90 0f 85}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VirLock_RPN_2147815370_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VirLock.RPN!MTB"
        threat_id = "2147815370"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VirLock"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {32 c2 88 07 46 47 49 83 f9 00 0f 85}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VirLock_RPO_2147815371_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VirLock.RPO!MTB"
        threat_id = "2147815371"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VirLock"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 06 32 c2 90 88 07 90 46 47 49 90 83 f9 00}  //weight: 1, accuracy: High
        $x_1_2 = {8a 06 90 32 c2 88 07 90 46 47 49 90 83 f9 00}  //weight: 1, accuracy: High
        $x_1_3 = {8a 06 32 c2 88 07 90 46 90 47 90 49 83 f9 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_VirLock_RPV_2147822344_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VirLock.RPV!MTB"
        threat_id = "2147822344"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VirLock"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8a 06 32 c2 90 88 07 90 46 90 e9}  //weight: 10, accuracy: High
        $x_5_2 = {47 49 90 83 f9 00 0f 85}  //weight: 5, accuracy: High
        $x_10_3 = {8a 06 32 c2 88 07 90 e9}  //weight: 10, accuracy: High
        $x_5_4 = {46 47 90 49 83 f9 00 90 0f 85}  //weight: 5, accuracy: High
        $x_10_5 = {8a 06 32 c2 e9}  //weight: 10, accuracy: High
        $x_5_6 = {88 07 46 47 49 83 f9 00 0f 85}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_5_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_VirLock_ARAA_2147907030_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VirLock.ARAA!MTB"
        threat_id = "2147907030"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VirLock"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8a 06 32 c2 88 07 46 47 49 e9 d7 ff ff ff}  //weight: 2, accuracy: High
        $x_2_2 = {83 f9 00 0f 85 12 00 00 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VirLock_SK_2147908941_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VirLock.SK!MTB"
        threat_id = "2147908941"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VirLock"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {32 c2 88 07 46 47 49 83 f9 00 e9 00 00 00 00}  //weight: 2, accuracy: High
        $x_2_2 = {8a 06 90 32 c2 90 88 07 46 47 90 49 83 f9 00 90 0f 85 ea ff ff ff}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

