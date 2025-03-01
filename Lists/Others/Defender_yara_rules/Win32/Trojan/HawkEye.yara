rule Trojan_Win32_HawkEye_A_2147740944_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/HawkEye.A"
        threat_id = "2147740944"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "HawkEye"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {c1 e0 1f c1 f8 1f 25 96 30 07 77 c1 e1 18 c1 f9 1f 81 e1 20 83 b8 ed 33 c8 8b c2 c1 e0 1d c1 f8 1f 25 19 c4 6d 07 33 c8 8b c2 c1 e0 19 c1 f8 1f 25 90 41 dc 76}  //weight: 10, accuracy: High
        $x_10_2 = {33 c8 8b c2 c1 e0 1a c1 f8 1f 25 c8 20 6e 3b 33 c8 8b c2 c1 e0 1e c1 f8 1f 25 2c 61 0e ee 33 c8 8b c2 c1 e0 1b c1 f8 1f 25 64 10 b7 1d}  //weight: 10, accuracy: High
        $x_10_3 = {33 c8 8b c2 c1 e0 1c c1 f8 1f 25 32 88 db 0e c1 ea 08 33 c8 33 d1 46}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_HawkEye_AS_2147743861_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/HawkEye.AS!!HawkEye.gen!AS"
        threat_id = "2147743861"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "HawkEye"
        severity = "Critical"
        info = "HawkEye: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "AS: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Start Menu\\Programs\\Startup\\bitsigd.url" ascii //weight: 1
        $x_1_2 = "HawkEye Keylogger" ascii //weight: 1
        $x_1_3 = "passwordfile" ascii //weight: 1
        $x_1_4 = "/upload.php" ascii //weight: 1
        $x_1_5 = "Reborn Stub.exe" ascii //weight: 1
        $x_1_6 = "/bitsigd/bitsigd.vbs" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_HawkEye_D_2147743897_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/HawkEye.D!MTB"
        threat_id = "2147743897"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "HawkEye"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Start Menu\\Programs\\Startup\\bitsigd.url" ascii //weight: 1
        $x_1_2 = "HawkEye Keylogger" ascii //weight: 1
        $x_1_3 = "passwordfile" ascii //weight: 1
        $x_1_4 = "/upload.php" ascii //weight: 1
        $x_1_5 = "Reborn Stub.exe" ascii //weight: 1
        $x_1_6 = "/bitsigd/bitsigd.vbs" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

