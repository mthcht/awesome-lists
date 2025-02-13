rule Trojan_Win32_WingoObfus_AC_2147900579_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/WingoObfus.AC!MTB"
        threat_id = "2147900579"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "WingoObfus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "estsoftservice.dat" ascii //weight: 1
        $x_1_2 = "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /d \"%s\" /t REG_SZ /v \"%s" ascii //weight: 1
        $x_1_3 = "dat.exe.gif.htm.jpg.mjs.pdf.png.svg.tmp.t" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

