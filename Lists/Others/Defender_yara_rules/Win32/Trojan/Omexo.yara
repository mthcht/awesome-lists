rule Trojan_Win32_Omexo_C_2147632119_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Omexo.C"
        threat_id = "2147632119"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Omexo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "URLDownloadToFileA" ascii //weight: 1
        $x_1_2 = "SOFTWARE\\Clients\\StartMenuInternet\\firefox.exe\\shell\\open\\command" ascii //weight: 1
        $x_1_3 = "\\\\?\\globalroot\\systemroot\\system32\\drivers\\etc\\hosts" ascii //weight: 1
        $x_1_4 = "\\\\.\\PhysicalDrive%d" ascii //weight: 1
        $x_1_5 = "Software\\Microsoft\\Internet Explorer\\TypedURLs" ascii //weight: 1
        $x_1_6 = "Software\\Microsoft\\Internet Explorer\\IntelliForms\\Storage2" ascii //weight: 1
        $x_1_7 = "PK11_CheckUserPassword" ascii //weight: 1
        $x_1_8 = "gethostbyname" ascii //weight: 1
        $x_1_9 = "cookiesie.z" ascii //weight: 1
        $x_1_10 = "cookies.z" ascii //weight: 1
        $x_1_11 = "keylog.z" ascii //weight: 1
        $x_1_12 = "certs.z" ascii //weight: 1
        $x_1_13 = "sysinfo.z" ascii //weight: 1
        $x_1_14 = "iexplore.exe|opera.exe|firefox.exe" ascii //weight: 1
        $x_1_15 = "src='http://%s/jbinfo.cgi?%s:%d'>" ascii //weight: 1
        $x_1_16 = "Global\\{721E3A61-883B-4144-BA81-1F965879E5C9}" ascii //weight: 1
        $x_1_17 = "AUTHINFO PASS " ascii //weight: 1
        $x_1_18 = "stealit" ascii //weight: 1
        $x_1_19 = "pass_log" ascii //weight: 1
        $x_1_20 = "sniff_log" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (14 of ($x*))
}

