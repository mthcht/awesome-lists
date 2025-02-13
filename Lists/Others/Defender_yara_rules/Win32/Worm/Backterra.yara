rule Worm_Win32_Backterra_H_2147597204_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Backterra.H"
        threat_id = "2147597204"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Backterra"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "2c49f800-c2dd-11cf-9ad6-0080c7e7b78d" wide //weight: 1
        $x_1_2 = "netsh firewall set allowedprogram" wide //weight: 1
        $x_1_3 = "tlntsvr.exe" wide //weight: 1
        $x_1_4 = "sc config tlntsvr start= auto & sc start tlntsvr" wide //weight: 1
        $x_1_5 = "tftp.exe" wide //weight: 1
        $x_1_6 = "s1e1t1u1p.exe" wide //weight: 1
        $x_1_7 = "Microsoft? Windows? Operating System" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

