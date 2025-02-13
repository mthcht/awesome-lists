rule Trojan_Win32_FrmBuk_A_2147741017_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FrmBuk.A"
        threat_id = "2147741017"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FrmBuk"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {81 f9 86 5d 00 00 75 c0 90 90 8b c6 90 90 90 ba 51 1a 00 00 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

