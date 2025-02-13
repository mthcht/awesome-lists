rule Trojan_Win32_SpyBanker_ARA_2147904299_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SpyBanker.ARA!MTB"
        threat_id = "2147904299"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SpyBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "JPS-VIRUSMAKER-4.0-8DE294F1-FD39-4526-BD8E-8B92700EA344" wide //weight: 2
        $x_2_2 = "\\DisableRegistryTools" wide //weight: 2
        $x_2_3 = "\\DisableTaskMgr" wide //weight: 2
        $x_2_4 = "\\DisableSR" wide //weight: 2
        $x_2_5 = "\\DisableCMD" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

