rule Trojan_Win64_FakeUpdate_GXM_2147975804_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/FakeUpdate.GXM!MTB"
        threat_id = "2147975804"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "FakeUpdate"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {48 8b cd c7 05 ?? ?? ?? ?? 44 69 73 61 f3 0f 7f 05 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? 62 6c 65 53 66 c7 05 ?? ?? ?? ?? 65 74 c6 05 ?? ?? ?? ?? 00 41 ff d0}  //weight: 10, accuracy: Low
        $x_1_2 = "SignalInitializeGetInstallDetailIsBrowserProcessIsExtensionPoint" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_FakeUpdate_ARAZ_2147982394_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/FakeUpdate.ARAZ!MTB"
        threat_id = "2147982394"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "FakeUpdate"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {41 8d 49 01 44 0f b6 c9 0f b6 c9 44 0f b6 1c 08 43 8d 14 13 44 0f b6 d2 0f b6 d2 0f b6 1c 10 88 1c 08 44 88 1c 10 43 8d 14 11 0f b6 d2 0f b6 14 10 41 30 10 49 83 c0 01 4d 39 c7 75 c3}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_FakeUpdate_ARAZ_2147982394_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/FakeUpdate.ARAZ!MTB"
        threat_id = "2147982394"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "FakeUpdate"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {41 8d 51 01 44 0f b6 ca 0f b6 d2 0f b6 1c 11 42 8d 04 13 44 0f b6 d0 0f b6 c0 0f b6 34 01 40 88 34 11 88 1c 01 43 8d 04 11 0f b6 c0 0f b6 04 01 41 30 00 49 83 c0 01 4d 39 d8 75 c4}  //weight: 4, accuracy: High
        $x_4_2 = "UpdaterSetup.exe" wide //weight: 4
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_FakeUpdate_GK_2147982540_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/FakeUpdate.GK!MTB"
        threat_id = "2147982540"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "FakeUpdate"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {ba 00 00 00 00 48 8b 4d b8 48 01 d1 48 8d 55 8c 49 89 d1 41 b8 04 00 00 00 48 89 c2 48 8b 05 ?? ?? ?? ?? ff d0}  //weight: 5, accuracy: Low
        $x_5_2 = {48 89 55 98 c6 45 ?? e2 c6 45 ?? 03 c6 45 ?? 04 c6 45 ?? 06 c7 45 ?? 01 00 00 00 c6 45 ?? 00 eb 2e 0f b6 55 fb 48 8b 45 b8 48 01 d0 0f b6 10 0f b6 45 fb 48 98 0f b6 44 05 ?? 38 c2 0f 94 c0 0f b6 c0 21 45 fc 0f b6 45 fb 83 c0 01 88 45 fb 0f b6 45 fb 3a 45 b7}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

