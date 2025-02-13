rule Ransom_Win32_BrightNight_MA_2147849122_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/BrightNight.MA!MTB"
        threat_id = "2147849122"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "BrightNight"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "rdprecovery@skiff.com" ascii //weight: 5
        $x_3_2 = "BrightNight" ascii //weight: 3
        $x_3_3 = "Y:\\X:\\W:\\V:\\U:\\T:\\S:\\R:\\Q:\\P:\\O:\\N:\\M:\\L:\\K:\\J:\\I:\\H:\\G:\\F:\\E:\\D:\\C:\\B:\\A:\\Z:\\" ascii //weight: 3
        $x_3_4 = "\\README.txt" ascii //weight: 3
        $x_3_5 = "SELECT * FROM MSAcpi_ThermalZoneTemperature" wide //weight: 3
        $x_1_6 = "Local\\RustBacktraceMutex" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

