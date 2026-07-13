rule Trojan_Win32_CodfishSupplyChain_RZT_2147973604_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CodfishSupplyChain.RZT!MTB"
        threat_id = "2147973604"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CodfishSupplyChain"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "command -v bun" wide //weight: 1
        $x_1_2 = "curl -fsSL" wide //weight: 1
        $x_1_3 = "bun run" wide //weight: 1
        $x_1_4 = "/.config/index.js" wide //weight: 1
        $x_1_5 = "2>&1 ||" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

