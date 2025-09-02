rule Trojan_Win64_DonutLoader_TL_2147940639_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DonutLoader.TL!MTB"
        threat_id = "2147940639"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DonutLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {41 b9 04 00 00 00 41 b8 00 30 00 00 31 c9 ba 00 00 50 00 ff d0 49 89 c5 48 85 c0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_DonutLoader_TL_2147940639_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DonutLoader.TL!MTB"
        threat_id = "2147940639"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DonutLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 98 0f b6 4c 05 80 8b 85 84 00 00 00 48 63 d0 48 8b 85 a0 00 00 00 48 01 d0 44 89 c2 31 ca 88 10 83 85 84 00 00 00 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_DonutLoader_BG_2147943164_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DonutLoader.BG!MTB"
        threat_id = "2147943164"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DonutLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {46 0f b6 0c 0a 45 89 c2 41 83 f2 ff 44 89 ca 44 21 d2 41 83 f1 ff 45 21 c8 44 09 c2 48 8b 00 48 8b 09 88 14 08}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_DonutLoader_ETL_2147944203_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DonutLoader.ETL!MTB"
        threat_id = "2147944203"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DonutLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 63 44 24 20 48 8d 0d 37 11 00 00 0f be 04 01 89 44 24 24 8b 44 24 20 99 83 e0 01 33 c2 2b c2 48 98 48 8b 4c 24 38 0f be 04 01 8b 4c 24 24 33 c8 8b c1 48 63 4c 24 20 48 8b 54 24 30 88 04 0a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_DonutLoader_C_2147944570_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DonutLoader.C!MTB"
        threat_id = "2147944570"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DonutLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {43 8b 14 91 39 c2 7e ?? 41 0f b6 14 00 41 8a 3c 03 48 ff c0 01 ca 48 63 d2 40 88 3c 16 eb}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_DonutLoader_PCO_2147945189_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DonutLoader.PCO!MTB"
        threat_id = "2147945189"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DonutLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {31 00 34 00 31 00 2e 00 39 00 38 00 2e 00 36 00 2e 00 31 00 34 00 3a 00 35 00 35 00 36 00 33 00 2f 00 [0-7] 2e 00 65 00 78 00 65 00}  //weight: 2, accuracy: Low
        $x_2_2 = {31 34 31 2e 39 38 2e 36 2e 31 34 3a 35 35 36 33 2f [0-7] 2e 65 78 65}  //weight: 2, accuracy: Low
        $x_1_3 = "executePowerShell" ascii //weight: 1
        $x_1_4 = "downloadAndRunFile" ascii //weight: 1
        $x_2_5 = "createRandomFolderInAppDataLocal" ascii //weight: 2
        $x_1_6 = "Add-MpPreference -ExclusionPath" ascii //weight: 1
        $x_1_7 = "restartAsAdmin" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((3 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_DonutLoader_GRR_2147945416_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DonutLoader.GRR!MTB"
        threat_id = "2147945416"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DonutLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {44 01 c2 0f b6 d2 44 29 c2 41 89 d3 48 63 d2 44 0f b6 04 14 46 88 04 14 88 0c 14 42 02 0c 14 0f b6 c9 0f b6 14 0c 30 13 48 83 c3 01 49 39 d9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_DonutLoader_CD_2147951153_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DonutLoader.CD!MTB"
        threat_id = "2147951153"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DonutLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {48 8b 4c 24 ?? 0f b6 8c 0c ?? ?? ?? ?? 31 c8 88 c2 48 8b 84 24 ?? ?? ?? ?? 48 8b 8c 24 ?? ?? ?? ?? 48 03 4c 24 ?? 88 14 08 48 8b 44 24}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

