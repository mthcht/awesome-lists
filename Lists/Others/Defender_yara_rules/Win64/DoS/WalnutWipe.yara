rule DoS_Win64_WalnutWipe_A_2147833459_0
{
    meta:
        author = "defender2yara"
        detection_name = "DoS:Win64/WalnutWipe.A!dha"
        threat_id = "2147833459"
        type = "DoS"
        platform = "Win64: Windows 64-bit platform"
        family = "WalnutWipe"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "400"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "/C \"C:\\Windows\\System32\\takeown.exe /F C:\\Windows\\System32\\w*exe &" wide //weight: 100
        $x_100_2 = "C:\\Windows\\System32\\icacls.exe C:\\Windows\\System32\\w*exe /deny *S-1-1-0:F &" wide //weight: 100
        $x_100_3 = "C:\\Windows\\System32\\takeown.exe /F C:\\Windows\\System32\\w*exe /A\"" wide //weight: 100
        $x_100_4 = "-r -s -q c:\\* & shutdown -s -t 00 -f" wide //weight: 100
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

