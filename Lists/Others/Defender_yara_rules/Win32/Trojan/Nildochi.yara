rule Trojan_Win32_Nildochi_STB_2147781983_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Nildochi.STB"
        threat_id = "2147781983"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Nildochi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\.\\\\Windo\\xx.FOP" ascii //weight: 1
        $x_1_2 = "%s\\regid.1991-06.com.microsoft.dat" ascii //weight: 1
        $x_1_3 = "http://%s/d1c.dat" ascii //weight: 1
        $x_1_4 = "/C netsh firewall set opmode mode=DISABLE" ascii //weight: 1
        $x_1_5 = "payload.dll" wide //weight: 1
        $x_1_6 = "blacksigns.txt" wide //weight: 1
        $x_1_7 = ".php?n=%s&c1=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

