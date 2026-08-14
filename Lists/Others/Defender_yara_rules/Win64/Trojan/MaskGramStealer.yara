rule Trojan_Win64_MaskGramStealer_AMK_2147960926_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/MaskGramStealer.AMK!MTB"
        threat_id = "2147960926"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "MaskGramStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 c1 83 e1 07 8a 4c 0c 08 41 32 0c 01 88 0c 02 48 ff c0 41 39 c0 7f ?? 4d 63 c0 42 c6 04 02 00 48 83 c4 10 5b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_MaskGramStealer_GHT_2147962294_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/MaskGramStealer.GHT!MTB"
        threat_id = "2147962294"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "MaskGramStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {49 89 c1 41 83 e1 03 46 8a 4c 0c ?? 44 32 0c 01 44 88 0c 02 48 ff c0 41 39 c0}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_MaskGramStealer_MK_2147965414_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/MaskGramStealer.MK!MTB"
        threat_id = "2147965414"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "MaskGramStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "35"
        strings_accuracy = "Low"
    strings:
        $x_35_1 = {44 89 c8 43 8d 2c 09 41 ff c1 0f af c6 44 8d 65 ?? 48 63 ed 4d 63 e4 8d 50 ?? 89 c8 42 32 14 23 32 14 2b 0f af c7 83 c0 ?? 41 32 04 0b 31 c2 41 88 14 0a 41 83 f9 ?? ?? ?? 45 31 c9 48 ff c1 41 39 c8}  //weight: 35, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_MaskGramStealer_AMG_2147973046_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/MaskGramStealer.AMG!MTB"
        threat_id = "2147973046"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "MaskGramStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 c8 43 8d 2c 09 0f af c6 41 02 04 0b 44 8d 65 01 48 63 ed 8d 50 ab 44 89 c8 4d 63 e4 41 ff c1 0f af c7 83 c0 3c 42 32 04 23 32 04 2b 29 c2 c0 c2 04 41 88 14 0a 41 83 f9 10}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_MaskGramStealer_VMX_2147976236_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/MaskGramStealer.VMX!MTB"
        threat_id = "2147976236"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "MaskGramStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {49 89 c2 48 ff c0 41 80 7c 01 ff 00 75 f2 31 c9 89 c8 99 41 f7 fa 48 63 d2 41 8a 04 11 41 32 04 0b 41 88 04 08 48 ff c1 48 83 f9 0b 75 e2 41 c6 40 0b 00}  //weight: 1, accuracy: High
        $x_1_2 = "/senttag" ascii //weight: 1
        $x_1_3 = "/getdll" ascii //weight: 1
        $x_1_4 = "/uploadfile" ascii //weight: 1
        $x_1_5 = "donflea247xw.cfd" ascii //weight: 1
        $x_1_6 = "Virtual Desktop" ascii //weight: 1
        $x_1_7 = "CheckRemoteDebuggerPresent" ascii //weight: 1
        $x_1_8 = "OutputDebugStringA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

