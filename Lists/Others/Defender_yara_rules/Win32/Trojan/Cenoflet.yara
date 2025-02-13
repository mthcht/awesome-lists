rule Trojan_Win32_Cenoflet_A_2147627010_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cenoflet.A"
        threat_id = "2147627010"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cenoflet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "start /low /min iexplore.exe \"http://shockwaveflashup.sytes.net/successful." ascii //weight: 1
        $x_1_2 = "%windir%\\system32\\ping.exe yc.shockwavesfx.com -n 1 -l 1" ascii //weight: 1
        $x_1_3 = "http://%ok%/proxy.pac" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

