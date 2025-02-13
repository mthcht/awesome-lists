rule Trojan_PowerShell_Shellcode_SV_2147819083_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:PowerShell/Shellcode.SV!MTB"
        threat_id = "2147819083"
        type = "Trojan"
        platform = "PowerShell: "
        family = "Shellcode"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "evcat_run.bat" wide //weight: 1
        $x_1_2 = "taskkill.exe /f /t /im tm_send_evcat3.exe" wide //weight: 1
        $x_1_3 = "taskkill.exe /f /t /im EV-CAT-KIOSK2.exe" wide //weight: 1
        $x_1_4 = "taskkill.exe /f /t /im evcat_end.exe" wide //weight: 1
        $x_1_5 = "taskkill.exe /f /t /im EndProcess.exe" wide //weight: 1
        $x_1_6 = "EV-CAT-KIOSK3.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

