rule Ransom_Win32_Critloki_A_2147687563_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Critloki.A"
        threat_id = "2147687563"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Critloki"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "TorLocker" wide //weight: 1
        $x_1_2 = "Payment Received. Proceed to decryption." ascii //weight: 1
        $x_1_3 = "reg add \"HKCU\\Control Panel\\Desktop\" /v Wallpaper /f /t REG_SZ /d \"C:\\TEMP\\wall.bmp\"" wide //weight: 1
        $x_1_4 = " -AvoidDiskWrites" wide //weight: 1
        $x_1_5 = " -DirReqStatistics" wide //weight: 1
        $x_1_6 = "k.php?affid=" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Ransom_Win32_Critloki_B_2147690771_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Critloki.B"
        threat_id = "2147690771"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Critloki"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "-AvoidDiskWrites 1 -ExcludeSingleHopRelays 0 -FascistFirewall 1 -DirReqStatistics 0" wide //weight: 1
        $x_1_2 = "incorrect attempt will reduce the time to destroy the private key" ascii //weight: 1
        $x_1_3 = {43 6c 69 63 6b 20 3c 3c 53 74 61 74 75 73 20 44 65 63 72 79 70 74 69 6f 6e 3e 3e 20 74 6f 20 73 65 65 20 74 68 65 20 66 69 6c 65 73 20 64 65 63 72 79 70 74 65 64 20 61 6e 64 20 73 74 61 74 75 73 20 61 66 74 65 72 20 69 74 73 20 64 6f 6e 65 00}  //weight: 1, accuracy: High
        $x_1_4 = {26 6e 66 69 6c 65 73 3d 00}  //weight: 1, accuracy: High
        $x_1_5 = {26 63 75 72 72 65 6e 63 79 3d 00}  //weight: 1, accuracy: High
        $x_1_6 = {73 75 72 65 20 79 6f 75 20 65 6e 74 65 72 65 64 20 79 6f 75 72 20 70 61 79 6d 65 6e 74 20 69 6e 66 6f 72 6d 61 74 69 6f 6e 20 63 6f 72 72 65 63 74 6c 79 3f 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

