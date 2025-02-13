rule Trojan_Win32_Rusei_A_2147629025_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rusei.A"
        threat_id = "2147629025"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rusei"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "zzzstopit.txt" ascii //weight: 1
        $x_1_2 = "Set zzzshll = Createobject (\"Wscript.Shell\")" ascii //weight: 1
        $x_1_3 = "zzzshll.regwrite (\"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\MS Office\")" ascii //weight: 1
        $x_1_4 = "http://xies.ru/?id=1" ascii //weight: 1
        $x_1_5 = "http://xies.ru/?id=3" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

