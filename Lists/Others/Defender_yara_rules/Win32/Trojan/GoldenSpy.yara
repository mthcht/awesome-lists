rule Trojan_Win32_GoldenSpy_A_2147758844_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GoldenSpy.A"
        threat_id = "2147758844"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GoldenSpy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "ningzhidata.com:9006/softServer/" ascii //weight: 2
        $x_1_2 = "Software\\IDG\\DA" ascii //weight: 1
        $x_1_3 = "nb_app_log_mutex" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GoldenSpy_VS_2147759075_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GoldenSpy.VS!MSR"
        threat_id = "2147759075"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GoldenSpy"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\VCProject\\dgs\\Release\\" ascii //weight: 1
        $x_1_2 = "taskkill /IM svm.exe /IM svmm.exe /F" ascii //weight: 1
        $x_1_3 = "Software\\Microsoft\\Windows\\CurrentVersion\\App Paths\\svm.exe" ascii //weight: 1
        $x_1_4 = "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\svm" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

