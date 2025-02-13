rule Worm_Win32_NoChod_B_2147594813_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/NoChod.B"
        threat_id = "2147594813"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "NoChod"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "90"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "ChodeBot Nathan" ascii //weight: 10
        $x_10_2 = "C:\\Program Files\\Messenger\\msmsgs.exe\\3" ascii //weight: 10
        $x_10_3 = "HTTP Flooding:" ascii //weight: 10
        $x_10_4 = "UDP Flooding:" ascii //weight: 10
        $x_10_5 = "Ping Flooding:" ascii //weight: 10
        $x_10_6 = "TCP Flooding:" ascii //weight: 10
        $x_10_7 = "netsh.exe firewall set opmode mode=disable profile=all" ascii //weight: 10
        $x_10_8 = "[SPREADMSN]: Started MSN spreader" wide //weight: 10
        $x_10_9 = "[MSNSPREAD]: Stopped MSN spreader" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

