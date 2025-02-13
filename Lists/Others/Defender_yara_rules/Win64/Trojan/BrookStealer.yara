rule Trojan_Win64_BrookStealer_DA_2147899867_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BrookStealer.DA!MTB"
        threat_id = "2147899867"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BrookStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "BrookStealer" ascii //weight: 1
        $x_1_2 = "GrabBrowserPasswords" ascii //weight: 1
        $x_1_3 = "browser.Credential" ascii //weight: 1
        $x_1_4 = "FirefoxCrackLoginData" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

