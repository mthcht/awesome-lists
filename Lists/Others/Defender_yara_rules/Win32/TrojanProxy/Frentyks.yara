rule TrojanProxy_Win32_Frentyks_A_2147652376_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Frentyks.A"
        threat_id = "2147652376"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Frentyks"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "dsth.dll" wide //weight: 1
        $x_1_2 = "&a_f=forum" wide //weight: 1
        $x_1_3 = "accd_fake" ascii //weight: 1
        $x_1_4 = "skynet" ascii //weight: 1
        $x_1_5 = "4jhnSH8DekS2b35Fb3NhdARN3K7uMHuBO/CcnAY7xgM=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanProxy_Win32_Frentyks_A_2147652376_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Frentyks.A"
        threat_id = "2147652376"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Frentyks"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "NTIONET6.SYS" wide //weight: 1
        $x_1_2 = "wusa32.exe" wide //weight: 1
        $x_1_3 = "dsth.dll" wide //weight: 1
        $x_1_4 = "inst.zip" wide //weight: 1
        $x_1_5 = "download_c.php?" wide //weight: 1
        $x_1_6 = "SystemPropertiesAdvancedViewer.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

