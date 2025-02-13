rule Trojan_Win32_Leafremote_A_2147728356_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Leafremote.A"
        threat_id = "2147728356"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Leafremote"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "60"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "net user guest 1234qweRR" ascii //weight: 10
        $x_10_2 = ",Administrator,Guest,vmware" ascii //weight: 10
        $x_10_3 = "echo signature=$CHICAGO$" ascii //weight: 10
        $x_10_4 = "WMIC USERACCOUNT WHERE \"Name = 'guest'" ascii //weight: 10
        $x_10_5 = "SECEDIT /CONFIGURE /CFG" ascii //weight: 10
        $x_10_6 = "failed w/err 0x%08lx" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

