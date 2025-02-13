rule PWS_Win32_Primarypass_A_2147714377_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Primarypass.A"
        threat_id = "2147714377"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Primarypass"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 ee fb ee ab 33 c9 57 0f b6 ?? ?? ?? ?? 00 d1 c0 33 c7 0f b6 ?? ?? ?? ?? 00 d1 c0 33 c7 0f b6 ?? ?? ?? ?? 00 d1 c0 33 c7 0f b6 ?? ?? ?? ?? 00 d1 c0 83 c1 04 33 c7 81 f9 00 01 00 00 72 c9}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b6 06 4a 33 c8 46 6a 08 58 f6 c1 01 74 06 81 f1 ?? ?? ?? ?? d1 e9 48 75 f0}  //weight: 1, accuracy: Low
        $x_1_3 = {56 56 68 e2 d4 ea d4 56 e8 ?? ?? ?? ?? 6a 04 68 00 10 00 00 57 56 ff d0 8b d8 85 db 74 38}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Primarypass_A_2147714377_1
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Primarypass.A"
        threat_id = "2147714377"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Primarypass"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "23"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "MAC=%02X%02X%02XINSTALL=%08X%08Xk" ascii //weight: 10
        $x_10_2 = {8a 04 39 30 04 16 41 33 c0 3b 4d 10 0f 4d c8}  //weight: 10, accuracy: High
        $x_1_3 = "%s\\WS_FTP\\WS_FTP.INI" wide //weight: 1
        $x_1_4 = "\\Preferences\\keychain.plist" wide //weight: 1
        $x_1_5 = "FROM moz_logins" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

