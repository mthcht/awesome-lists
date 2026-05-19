rule Trojan_Win32_MiniPlasma_LVG_2147969520_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MiniPlasma.LVG!MTB"
        threat_id = "2147969520"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MiniPlasma"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cd /d C:\\test && curl -L -O" ascii //weight: 1
        $x_1_2 = "//github.com/Nightmare-Eclipse/MiniPlasma/releases/download/main-release/PoC_AbortHydration_ArbitraryRegKey_EoP.exe" ascii //weight: 1
        $x_1_3 = "Admin Done" ascii //weight: 1
        $x_1_4 = "md C:\\test 2>nul" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

