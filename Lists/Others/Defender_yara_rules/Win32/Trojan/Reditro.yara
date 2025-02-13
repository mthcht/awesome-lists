rule Trojan_Win32_Reditro_A_2147635823_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Reditro.A"
        threat_id = "2147635823"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Reditro"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "batchfile.bat" ascii //weight: 1
        $x_1_2 = "echo.209.222.138.10" ascii //weight: 1
        $x_1_3 = "www.facebook.com>>%windir%\\System32\\drivers\\etc\\hosts" ascii //weight: 1
        $x_1_4 = "echo Instaling" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

