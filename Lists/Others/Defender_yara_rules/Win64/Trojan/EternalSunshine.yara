rule Trojan_Win64_EternalSunshine_A_2147963145_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/EternalSunshine.A!dha"
        threat_id = "2147963145"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "EternalSunshine"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "E:\\mklgs\\" ascii //weight: 1
        $x_1_2 = "CmfcmklgDlg" ascii //weight: 1
        $x_1_3 = "CmfcmklgApp" ascii //weight: 1
        $x_1_4 = "taskkill /im keepass.exe /t /f" ascii //weight: 1
        $x_1_5 = "taskkill /im svehost.exe /t /f" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

