rule Trojan_Win64_RustStealer_RPY_2147902566_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/RustStealer.RPY!MTB"
        threat_id = "2147902566"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "RustStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Fud Me by New Coder Rust" ascii //weight: 1
        $x_1_2 = "Secure_Vortex" ascii //weight: 1
        $x_1_3 = "fhnir" ascii //weight: 1
        $x_1_4 = "NtWriteVirtualMemory" ascii //weight: 1
        $x_1_5 = "panicked" ascii //weight: 1
        $x_1_6 = "GoAway" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_RustStealer_DA_2147926526_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/RustStealer.DA!MTB"
        threat_id = "2147926526"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "RustStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "powershell -NoProfile -NonInteractive -WindowStyle Hidden -Command" ascii //weight: 10
        $x_10_2 = "Add-MpPreference -ExclusionProcess" ascii //weight: 10
        $x_1_3 = "github.com" ascii //weight: 1
        $x_1_4 = "APPDATA" ascii //weight: 1
        $x_1_5 = "mutex poisoned" ascii //weight: 1
        $x_1_6 = "Once instance has previously been poisoned" ascii //weight: 1
        $x_1_7 = "vel criar o arquivo .bat." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_RustStealer_GTT_2147926858_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/RustStealer.GTT!MTB"
        threat_id = "2147926858"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "RustStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {33 20 3e 20 6e ?? 6c 0a 64 65 ?? 20 22 22 0a 64 65 6c 20 22 25 ?? ?? ?? ?? 0a 00}  //weight: 10, accuracy: Low
        $x_1_2 = "vel criar o arquivo .bat" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

