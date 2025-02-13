rule Backdoor_Win32_Sensode_F_2147689138_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Sensode.F"
        threat_id = "2147689138"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Sensode"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {58 00 4d 00 4b 00 44 00 [0-6] 46 00 49 00 4c 00 45 00 [0-6] 53 00 54 00 4f 00 52 00 [0-6] 52 00 45 00 54 00 52 00 [0-6] 53 00 49 00 5a 00 45 00 [0-6] 52 00 45 00 53 00 54 00 [0-6] 45 00 58 00 45 00 43 00 [0-6] 52 00 4e 00 54 00 4f 00}  //weight: 10, accuracy: Low
        $x_10_2 = {58 4d 4b 44 [0-6] 46 49 4c 45 [0-6] 53 54 4f 52 [0-6] 52 45 54 52 [0-6] 53 49 5a 45 [0-6] 52 45 53 54 [0-6] 45 58 45 43 [0-6] 52 4e 54 4f}  //weight: 10, accuracy: Low
        $x_1_3 = "zxplug -add getxxx c:\\xyz.dll" ascii //weight: 1
        $x_2_4 = "\\CurrentControlSet\\Control\\zxplug" ascii //weight: 2
        $x_1_5 = "%.2d-%.2d-%.2d %.2d:%.2d:%.2d" ascii //weight: 1
        $x_1_6 = "-get ftp://user:pass" ascii //weight: 1
        $x_1_7 = "%s SP%d.%d(%d)" ascii //weight: 1
        $x_2_8 = "202.96.128.166" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_2_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Sensode_G_2147689140_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Sensode.G"
        threat_id = "2147689140"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Sensode"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "-hacksite" ascii //weight: 1
        $x_1_2 = "zxarps.exe -idx 0 -ip 192.168.0.2-192.168.0.99 -port 80 -hacksite 222.2.2.2" ascii //weight: 1
        $x_1_3 = "-hackdns [string]  DNS" ascii //weight: 1
        $x_1_4 = "Restoring the ARPTable......" ascii //weight: 1
        $x_1_5 = "Killing the SpoofThread......" ascii //weight: 1
        $x_1_6 = "hacksite: %s -> %s." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Backdoor_Win32_Sensode_H_2147689735_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Sensode.H"
        threat_id = "2147689735"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Sensode"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "ZXShell" ascii //weight: 5
        $x_5_2 = "Uptime: %-.2d Days %-.2d Hours %-.2d Minutes %-.2d Seconds" ascii //weight: 5
        $x_5_3 = "Shell setup information:" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

