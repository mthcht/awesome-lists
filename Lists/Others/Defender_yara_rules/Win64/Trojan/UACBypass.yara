rule Trojan_Win64_UACBypass_YTB_2147922270_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/UACBypass.YTB!MTB"
        threat_id = "2147922270"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "UACBypass"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:/Temp/firedrill-main/firedrill-main/cmd/uac_bypass/main.go" ascii //weight: 1
        $x_1_2 = "pkg/behaviours/bypass_fodhelper" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_UACBypass_MX_2147945757_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/UACBypass.MX!MTB"
        threat_id = "2147945757"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "UACBypass"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DriverInstall\\bin\\TaskScheduler_x64.pdb" ascii //weight: 1
        $x_1_2 = "bin\\BypassUACDll_x86.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_UACBypass_HS_2147959021_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/UACBypass.HS!MTB"
        threat_id = "2147959021"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "UACBypass"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Release\\BypassUAC.pdb" ascii //weight: 1
        $x_1_2 = "c:\\users\\public\\test.exe" wide //weight: 1
        $x_1_3 = "\\explorer.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

