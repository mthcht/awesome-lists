rule Trojan_Win32_HoneyMyte_GVA_2147941645_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/HoneyMyte.GVA!MTB"
        threat_id = "2147941645"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "HoneyMyte"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 08 69 88 ec 01 00 00 fd 43 03 00 81 c1 c3 9e 26 00 8b 55 08 89 8a ec 01 00 00 8b 45 08 8b 80 ec 01 00 00 5f 5e 5b 81 c4 c0 00 00 00 3b ec}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_HoneyMyte_AO_2147941837_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/HoneyMyte.AO!MTB"
        threat_id = "2147941837"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "HoneyMyte"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Global\\fjqwlfjklwqgh" ascii //weight: 2
        $x_2_2 = "Global\\sdjsalk_once" ascii //weight: 2
        $x_1_3 = "C:\\ProgramData\\NEWFYGO" wide //weight: 1
        $x_1_4 = "grant:r Everyone:(OI)(CI)" wide //weight: 1
        $x_1_5 = "cmd.exe /c icacls" wide //weight: 1
        $x_1_6 = "fs:NTFS /Q /Y" wide //weight: 1
        $x_1_7 = "1.txt" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

