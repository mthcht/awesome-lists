rule Trojan_Win32_Genbhv_A_2147741352_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Genbhv.A"
        threat_id = "2147741352"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Genbhv"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "System\\CurrentControlSet\\Control\\Keyboard Layouts\\%.8x" ascii //weight: 1
        $x_1_2 = "TTimePasswordAutoForm" ascii //weight: 1
        $x_1_3 = "PasswordEditl" ascii //weight: 1
        $x_1_4 = "OnPassword$" ascii //weight: 1
        $x_1_5 = "\\DRIVERS\\%s\\DB OPEN" ascii //weight: 1
        $x_1_6 = "Conuserfig.dat" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Genbhv_D_2147745509_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Genbhv.D!MSR"
        threat_id = "2147745509"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Genbhv"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c0 0f b6 88 ?? ?? ?? ?? 0f b6 90 ?? ?? ?? ?? 2a 88 ?? ?? ?? ?? 2a 90 ?? ?? ?? ?? 88 88 ?? ?? ?? ?? 0f b6 88 ?? ?? ?? ?? 2a 88 ?? ?? ?? ?? 88 90 ?? ?? ?? ?? 0f b6 90 ?? ?? ?? ?? 2a 90 ?? ?? ?? ?? 88 88 ?? ?? ?? ?? 88 90 ?? ?? ?? ?? 83 c0 04 83 f8 10 7c ac c3}  //weight: 1, accuracy: Low
        $x_1_2 = {40 49 83 f8 10 7c f3 06 00 00 88}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

