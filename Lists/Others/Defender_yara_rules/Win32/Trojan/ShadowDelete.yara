rule Trojan_Win32_ShadowDelete_BB_2147937655_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ShadowDelete.BB!MTB"
        threat_id = "2147937655"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ShadowDelete"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {77 00 62 00 61 00 64 00 6d 00 69 00 6e 00 [0-16] 64 00 65 00 6c 00 65 00 74 00 65 00 [0-16] 63 00 61 00 74 00 61 00 6c 00 6f 00 67 00}  //weight: 10, accuracy: Low
        $x_10_2 = {62 00 63 00 64 00 65 00 64 00 69 00 74 00 [0-16] 2f 00 73 00 65 00 74 00 [0-16] 64 00 65 00 66 00 61 00 75 00 6c 00 74 00 [0-16] 72 00 65 00 63 00 6f 00 76 00 65 00 72 00 79 00 65 00 6e 00 61 00 62 00 6c 00 65 00 64 00 [0-16] 6e 00 6f 00}  //weight: 10, accuracy: Low
        $x_10_3 = {62 00 63 00 64 00 65 00 64 00 69 00 74 00 [0-16] 2f 00 73 00 65 00 74 00 [0-16] 64 00 65 00 66 00 61 00 75 00 6c 00 74 00 [0-16] 62 00 6f 00 6f 00 74 00 73 00 74 00 61 00 74 00 75 00 73 00 70 00 6f 00 6c 00 69 00 63 00 79 00 [0-16] 69 00 67 00 6e 00 6f 00 72 00 65 00 61 00 6c 00 6c 00 66 00 61 00 69 00 6c 00 75 00 72 00 65 00 73 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_ShadowDelete_CC_2147942696_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ShadowDelete.CC!MTB"
        threat_id = "2147942696"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ShadowDelete"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "vssadmin delete shadows /all" wide //weight: 1
        $x_1_2 = "wmic shadowcopy delete" wide //weight: 1
        $x_1_3 = "bcdedit /set {default} bootstatuspolicy ignoreallfailures" wide //weight: 1
        $x_1_4 = "bcdedit /set {default} recoveryenabled no" wide //weight: 1
        $x_1_5 = "wbadmin delete catalog -quiet" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

