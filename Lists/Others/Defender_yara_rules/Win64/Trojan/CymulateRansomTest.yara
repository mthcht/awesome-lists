rule Trojan_Win64_CymulateRansomTest_LK_2147846290_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CymulateRansomTest.LK!MTB"
        threat_id = "2147846290"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CymulateRansomTest"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Users\\YoavShaharabani\\source\\repos\\windows-scenarios\\Payloads\\NativeRansomeware\\x64\\RemoteKey_" ascii //weight: 1
        $x_1_2 = "APT_SCENARIO" ascii //weight: 1
        $x_1_3 = "attack_id" ascii //weight: 1
        $x_1_4 = "scenario_id" ascii //weight: 1
        $x_1_5 = ".CymCrypt" wide //weight: 1
        $x_1_6 = "get-encryption-key?token=" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CymulateRansomTest_MKC_2147846308_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CymulateRansomTest.MKC!MTB"
        threat_id = "2147846308"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CymulateRansomTest"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {45 30 01 4c 8b 49 ?? 41 0f b6 41 ?? 44 0f b6 44 08 ?? 45 30 41 ?? 41 b9 ?? ?? ?? ?? 4c 8b 41 ?? 41 0f b6 40 ?? 0f b6 54 08 ?? 41 30 50 ?? 4c 8b 41 ?? 41 0f b6 40 ?? 0f b6 54 08 ?? 41 0f b6 c2 41 30 50 ?? 45 02 d2 c0 e8 07 0f b6 c0 6b d0 ?? 41 32 d2 41 b2 ?? 41 88 13}  //weight: 1, accuracy: Low
        $x_1_2 = {41 0f b6 c2 41 80 c2 04 4e 8d 04 0a 0f b6 54 10 ?? 41 30 50 ?? 48 8b 41 18 4a 8d 14 08 42 0f b6 44 08 ?? 30 02 48 8b 41 ?? 49 8d 14 01 41 0f b6 44 01 ?? 30 42 ?? 48 8b 41 ?? 49 8d 14 01 41 0f b6 44 01 ?? 30 42 02 4d 8d 49 04 41 80 fa ?? 72}  //weight: 1, accuracy: Low
        $x_1_3 = "\\Users\\YoavShaharabani\\source\\repos\\windows-scenarios\\Payloads\\NativeRansomewareDll\\x64\\RandomKey_ManualAes_Overwrite\\NativeRansomewareDll.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CymulateRansomTest_MKW_2147846309_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CymulateRansomTest.MKW!MTB"
        threat_id = "2147846309"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CymulateRansomTest"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b9 04 00 00 00 2a ca 41 0f b6 00 02 c8 80 f1 28 80 c1 0c 41 88 08 48 ff c2 4d 8d 40 ?? 48 83 fa ?? 72}  //weight: 1, accuracy: Low
        $x_1_2 = {80 f1 01 c0 e1 05 80 c1 ?? 88 08 c6 40 ?? ?? e9 ?? ?? ?? ?? b8 ?? ?? ?? ?? 4d 39 1e 7d 05 88 02 48 ff c3 8a 84 24 ?? ?? ?? ?? 4c 8d 63 ?? 34 01 41 bf ?? ?? ?? ?? 44 0f b6 e8 41 b8 ?? ?? ?? ?? 41 8b ed}  //weight: 1, accuracy: Low
        $x_1_3 = {5c 55 73 65 72 73 5c 59 6f 61 76 53 68 61 68 61 72 61 62 61 6e 69 5c 73 6f 75 72 63 65 5c 72 65 70 6f 73 5c 77 69 6e 64 6f 77 73 2d 73 63 65 6e 61 72 69 6f 73 5c 50 61 79 6c 6f 61 64 73 5c 4e 61 74 69 76 65 52 61 6e 73 6f 6d 65 77 61 72 65 44 6c 6c 5c 78 36 34 5c [0-48] 5c 4e 61 74 69 76 65 52 61 6e 73 6f 6d 65 77 61 72 65 44 6c 6c 2e 70 64 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CymulateRansomTest_MKD_2147846567_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CymulateRansomTest.MKD!MTB"
        threat_id = "2147846567"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CymulateRansomTest"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 e8 48 81 c0 b8 00 00 00 48 c7 c1 0b 06 00 00 48 c7 c2 ?? ?? ?? ?? 30 10 48 ff c0 48 ff c9 0f 85}  //weight: 1, accuracy: Low
        $x_1_2 = "encryption_path:string:c:\\programdata\\cymulate\\EDR" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

