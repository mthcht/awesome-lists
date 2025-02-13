rule Trojan_Win32_Kimusky_PA_2147745824_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kimusky.PA!MTB"
        threat_id = "2147745824"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kimusky"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/s /n /i NewACt.dat" ascii //weight: 1
        $x_1_2 = "rns.bat" ascii //weight: 1
        $x_1_3 = {3a 52 65 70 65 61 74 31 0d 0a 64 65 6c 20 22 25 73 22 0d 0a 69 66 20 65 78 69 73 74 20 22 25 73 22 20 67 6f 74 6f 20 52 65 70 65 61 74 31 0d 0a 64 65 6c 20 22 25 73 22}  //weight: 1, accuracy: High
        $x_1_4 = "antichrist.or.kr" ascii //weight: 1
        $x_1_5 = "F.php" ascii //weight: 1
        $x_1_6 = "/data/cheditor/dir1" ascii //weight: 1
        $x_1_7 = "Papua gloria" ascii //weight: 1
        $x_1_8 = "\\makeHwp\\Bin\\makeHwp.pdb" ascii //weight: 1
        $x_1_9 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_10 = "lyric" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

