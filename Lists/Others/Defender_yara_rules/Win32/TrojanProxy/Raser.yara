rule TrojanProxy_Win32_Raser_2147582261_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Raser"
        threat_id = "2147582261"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Raser"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "121"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Proxy-Authenticate: Basic realm=\"proxy\"" ascii //weight: 10
        $x_10_2 = "ftp@ya.ru" ascii //weight: 10
        $x_10_3 = "System\\ControlSet001\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\StandardProfile\\GloballyOpenPorts\\List" ascii //weight: 10
        $x_10_4 = "Mozilla/4.0 (compatible)" ascii //weight: 10
        $x_10_5 = "%s/r.php?" ascii //weight: 10
        $x_10_6 = "check.dat" ascii //weight: 10
        $x_10_7 = "PASS %.64s" ascii //weight: 10
        $x_10_8 = "USER %.32s" ascii //weight: 10
        $x_10_9 = "<body><h2>407 Proxy Authentication Required</h2><h3>Access to requested resource disallowed by administrator or you need valid username/password to use this resource</h3></body></html>" ascii //weight: 10
        $x_10_10 = "HTTP/1.0 502 Bad Gateway" ascii //weight: 10
        $x_10_11 = "<html><head><title>400 Bad Request</title></head>" ascii //weight: 10
        $x_10_12 = "<body><h2>502 Bad Gateway</h2><h3>Host Not Found or connection failed</h3></body></html>" ascii //weight: 10
        $x_1_13 = "prefc_%u.exe" ascii //weight: 1
        $x_1_14 = "prefc%u.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((12 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

