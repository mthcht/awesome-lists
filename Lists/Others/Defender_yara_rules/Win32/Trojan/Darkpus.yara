rule Trojan_Win32_Darkpus_A_2147656140_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Darkpus.A"
        threat_id = "2147656140"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Darkpus"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Preferences\\keychain.plist" ascii //weight: 1
        $x_1_2 = "\\WS_FTP\\Sites\\ws_ftp.ini" ascii //weight: 1
        $x_1_3 = {00 75 70 6c 6f 61 64 2e 70 68 70 00}  //weight: 1, accuracy: High
        $x_1_4 = "TBotThread_" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

