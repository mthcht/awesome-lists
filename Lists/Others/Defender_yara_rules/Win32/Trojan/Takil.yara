rule Trojan_Win32_Takil_A_2147643226_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Takil.A"
        threat_id = "2147643226"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Takil"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "net stop dhcp-client" ascii //weight: 1
        $x_1_2 = "taskkill /f  /im iexplore.exe" ascii //weight: 1
        $x_1_3 = "assoc .exe=WMAFile" ascii //weight: 1
        $x_1_4 = "Reg Add \"HKCU\\Control Panel\\Mouse\" /v SwapMouseButtons" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

