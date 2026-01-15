rule Trojan_Win64_Rusty_AR_2147961130_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Rusty.AR!AMTB"
        threat_id = "2147961130"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Rusty"
        severity = "Critical"
        info = "AMTB: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "193.161.193.99" ascii //weight: 5
        $x_5_2 = "cleanup.bat" ascii //weight: 5
        $x_1_3 = "uninstallkillcd cmd/CErr:" ascii //weight: 1
        $x_1_4 = "taskkill /F /IM \"\" >nul 2>&1" ascii //weight: 1
        $x_1_5 = "timeout /t 1 /nobreak >nul" ascii //weight: 1
        $x_1_6 = "HealthMon.execmdattrib +h" ascii //weight: 1
        $x_1_7 = "a spawned task panicked and the runtime is configured to shut down on unhandled panic" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

