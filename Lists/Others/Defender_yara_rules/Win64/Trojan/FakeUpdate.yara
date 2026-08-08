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

