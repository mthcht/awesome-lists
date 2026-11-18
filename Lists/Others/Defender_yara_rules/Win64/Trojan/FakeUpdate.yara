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
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {41 8d 51 01 44 0f b6 ca 0f b6 d2 0f b6 1c 11 42 8d 04 13 44 0f b6 d0 0f b6 c0 0f b6 34 01 40 88 34 11 88 1c 01 43 8d 04 11 0f b6 c0 0f b6 04 01 41 30 00 49 83 c0 01 4d 39 d8 75 c4}  //weight: 4, accuracy: High
        $x_4_2 = "UpdaterSetup.exe" wide //weight: 4
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

