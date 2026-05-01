rule Trojan_Win32_Cyclun_ECP_2147940177_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cyclun.ECP!MTB"
        threat_id = "2147940177"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cyclun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {b9 f7 68 00 00 99 f7 f9 6a 00 80 c2 02 30 96}  //weight: 5, accuracy: High
        $x_5_2 = {8d 4b 01 f7 e6 33 db 46 c1 ea 02 8d 04 92 3b f8 0f 45 d9 81 fe}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Cyclun_NR_2147968207_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cyclun.NR!MTB"
        threat_id = "2147968207"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cyclun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {83 3f 00 75 29 8b 45 0c 8b 70 38 85 f6 7e 4a 8b 47 fc 03 45 f8 6a 04 68 00 10 00 00 56 50 ff d2 56 6a 00 50 89 47 f8}  //weight: 2, accuracy: High
        $x_1_2 = {8b 45 10 43 8b 75 f8 83 c7 28 8b 00 0f b7 40 06 3b d8 7c 93}  //weight: 1, accuracy: High
        $x_1_3 = "add \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\" /v \"Startup\" /t REG_SZ /d \"%s\" /f" ascii //weight: 1
        $x_1_4 = "reg.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

