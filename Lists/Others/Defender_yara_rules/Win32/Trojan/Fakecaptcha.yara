rule Trojan_Win32_Fakecaptcha_BA_2147980616_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fakecaptcha.BA!MTB"
        threat_id = "2147980616"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fakecaptcha"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "40"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "powershell.exe" wide //weight: 10
        $x_10_2 = "-WI MInimiZ" wide //weight: 10
        $x_10_3 = "Get-ChildItem Alias" wide //weight: 10
        $x_10_4 = {73 00 74 00 69 00 72 00 ?? ?? 72 00 79 00 2e 00 6e 00 65 00 74 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

