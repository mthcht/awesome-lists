rule Trojan_Win32_ProtectorEnigma_RF_2147788215_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ProtectorEnigma.RF!MTB"
        threat_id = "2147788215"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ProtectorEnigma"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RegCloseKey" ascii //weight: 1
        $x_1_2 = "ShellExecuteA" ascii //weight: 1
        $x_1_3 = "44 CALIBER" wide //weight: 1
        $x_1_4 = "Insidious.exe" wide //weight: 1
        $x_1_5 = "FuckTheSystem Copyright" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

