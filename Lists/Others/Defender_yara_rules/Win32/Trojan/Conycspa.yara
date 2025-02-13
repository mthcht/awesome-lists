rule Trojan_Win32_Conycspa_C_2147593995_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Conycspa.C"
        threat_id = "2147593995"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Conycspa"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/aff-light/affcgi/installed.fcgi?userid=20001" ascii //weight: 1
        $x_1_2 = "/aff-light/affcgi/install.php?userid=20001" ascii //weight: 1
        $x_1_3 = "\\ServicePackFiles\\i386\\mswsock.dll" ascii //weight: 1
        $x_1_4 = "http://litlemouse.info/a/49.dat" ascii //weight: 1
        $x_1_5 = "/cgi-script/repeaterm3.fcgi?v5" ascii //weight: 1
        $x_1_6 = "Content-Type: image/x-gif" ascii //weight: 1
        $x_1_7 = "Content-Type: image/gif" ascii //weight: 1
        $x_1_8 = "\\dllcache\\mswsock.dll" ascii //weight: 1
        $x_1_9 = "InternetCrackUrlA" ascii //weight: 1
        $x_1_10 = "\\mswsockhh.dll" ascii //weight: 1
        $x_1_11 = "gif/chgif.exe" ascii //weight: 1
        $x_1_12 = "\\mswsock.bak" ascii //weight: 1
        $x_1_13 = "png/png.exe" ascii //weight: 1
        $x_1_14 = "jpg/jpg.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (12 of ($x*))
}

