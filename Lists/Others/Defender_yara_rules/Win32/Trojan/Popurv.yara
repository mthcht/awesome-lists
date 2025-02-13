rule Trojan_Win32_Popurv_A_2147712923_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Popurv.A"
        threat_id = "2147712923"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Popurv"
        severity = "Low"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Software\\WinService\\" ascii //weight: 1
        $x_3_2 = "\\\\Mac\\Home\\Desktop\\winserv\\winserviceSources\\winserviceSources\\Debug\\Updater.pdb" ascii //weight: 3
        $x_2_3 = "StartPopup failed, error code = %d" ascii //weight: 2
        $x_1_4 = "PopupURL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

