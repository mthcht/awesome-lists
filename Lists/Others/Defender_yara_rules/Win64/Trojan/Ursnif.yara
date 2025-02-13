rule Trojan_Win64_Ursnif_CC_2147815018_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Ursnif.CC!MTB"
        threat_id = "2147815018"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "WinHttpOpenRequest" ascii //weight: 3
        $x_3_2 = "WinHttpReadData" ascii //weight: 3
        $x_3_3 = "WinHttpAddRequestHeaders" ascii //weight: 3
        $x_3_4 = "SetupDiGetDeviceRegistryPropertyA" ascii //weight: 3
        $x_3_5 = "AVIFileExit" ascii //weight: 3
        $x_3_6 = "AVIFileOpenW" ascii //weight: 3
        $x_3_7 = "turbos.dll" ascii //weight: 3
        $x_3_8 = "MSVCcvidMRLE" ascii //weight: 3
        $x_3_9 = "ConvertStringSecurityDescriptorToSecurityDescriptorA" ascii //weight: 3
        $x_3_10 = "ShellExecuteW" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Ursnif_RC_2147832246_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Ursnif.RC!MTB"
        threat_id = "2147832246"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 b9 01 00 00 00 89 41 08 8b 44 24 48 49 8b cf 41 2b c5 03 44 24 4c 46 8d 44 30 12 e8 ?? ?? ?? ?? 8b 45 0c 41 ff c5 2b 45 08 49 81 c7 00 10 00 00 03 45 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Ursnif_AMAB_2147888268_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Ursnif.AMAB!MTB"
        threat_id = "2147888268"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 2b ca 83 7c 24 28 00 8b 04 11 44 8b c8 74 ?? 85 c0 75 ?? 44 8d 40 01 eb ?? 45 2b d3 41 03 c2 45 8b d1 89 02 48 83 c2 04 41 83 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Ursnif_ZA_2147890013_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Ursnif.ZA!MTB"
        threat_id = "2147890013"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b ca d3 c7 8b ce 33 fe d3 c3 33 da 8b d5 8b cb 8b ef 8b 7c 24 ?? 2b 78 ?? 8b da 2b 58 ?? 8d 54 09 ?? 0f af d1 8d 74 2d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Ursnif_AC_2147896087_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Ursnif.AC!MTB"
        threat_id = "2147896087"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "Grabbing IE cookies" ascii //weight: 3
        $x_3_2 = "grcook64.pdb" ascii //weight: 3
        $x_3_3 = "NSS_Shutdown" ascii //weight: 3
        $x_3_4 = "BCryptDestroyKey" ascii //weight: 3
        $x_3_5 = "PK11_FreeSlot" ascii //weight: 3
        $x_3_6 = "PK11SDR_Decrypt" ascii //weight: 3
        $x_3_7 = "cookies.sqlite" ascii //weight: 3
        $x_3_8 = "*.txt" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Ursnif_CCHT_2147903239_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Ursnif.CCHT!MTB"
        threat_id = "2147903239"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 41 08 8b 4b 0c 8d 2c 11 48 03 ce 33 6c 24 20 33 6c 24 24 44 8d 45 0d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

