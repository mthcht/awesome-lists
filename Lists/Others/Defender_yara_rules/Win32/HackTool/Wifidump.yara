rule HackTool_Win32_Wifidump_2147840189_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Wifidump"
        threat_id = "2147840189"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Wifidump"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "//securityxploded.com/wifi-password-dump.php" ascii //weight: 1
        $x_1_2 = "WiFiPasswordDump" ascii //weight: 1
        $x_1_3 = "StartWiFiPasswordRecovery" ascii //weight: 1
        $x_1_4 = "SecurityXploded" ascii //weight: 1
        $x_1_5 = "WiFiPasswordService.exe" ascii //weight: 1
        $x_1_6 = "WiFi Password Decryptor" ascii //weight: 1
        $x_1_7 = "\\Temp\\wifi_output.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

