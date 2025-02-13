rule TrojanDownloader_Win32_Fsizedol_A_2147709722_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Fsizedol.A!bit"
        threat_id = "2147709722"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Fsizedol"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_2 = "Host: hello.php" ascii //weight: 1
        $x_1_3 = "\\last.exe" ascii //weight: 1
        $x_1_4 = "data=eyJ1dWlkIjoiIiwiYnVpbGQiOjYsIm9zIjoiV2luV2luZG93cyIsIm5hdCI6MH0=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

