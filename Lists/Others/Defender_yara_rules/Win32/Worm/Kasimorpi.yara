rule Worm_Win32_Kasimorpi_A_2147633558_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Kasimorpi.A"
        threat_id = "2147633558"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Kasimorpi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Metamorphica\\Project1.vbp" wide //weight: 1
        $x_1_2 = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\SearchFile" wide //weight: 1
        $x_1_3 = "\\CurrentVersion\\Run\\Antivirus" wide //weight: 1
        $x_1_4 = "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\NoRun" wide //weight: 1
        $x_1_5 = "Apakah Saya Lebih Tampan Dari V-Maker Lainya" wide //weight: 1
        $x_1_6 = "Terimakasih Anda Telah Mencintaiku Apa Adanya" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

