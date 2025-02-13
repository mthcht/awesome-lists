rule Trojan_Win64_TrapStealer_DA_2147905280_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/TrapStealer.DA!MTB"
        threat_id = "2147905280"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "TrapStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Go build ID:" ascii //weight: 10
        $x_1_2 = "kbinani/screenshot" ascii //weight: 1
        $x_1_3 = "main.antidebugger" ascii //weight: 1
        $x_1_4 = "main.decryptAllPasswords" ascii //weight: 1
        $x_1_5 = "main.decryptAllCookies" ascii //weight: 1
        $x_1_6 = "main.saveWindowsWallpapers" ascii //weight: 1
        $x_1_7 = "main.getAutofill" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

