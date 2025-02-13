rule Worm_Win32_Flewon_B_2147597784_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Flewon.B"
        threat_id = "2147597784"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Flewon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "141"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "msvbvm60.dll\\3" ascii //weight: 100
        $x_11_2 = "Scripting.FileSystemObject" wide //weight: 11
        $x_10_3 = "A*\\AC:\\Documents and Settings\\HailuYa.ETHAIR\\Desktop\\pass\\asterie.vbp" wide //weight: 10
        $x_5_4 = "C:\\putmethat.txt" wide //weight: 5
        $x_5_5 = "http://mail.madcoffee.com/index.php" wide //weight: 5
        $x_5_6 = "bttnserv.exe" wide //weight: 5
        $x_5_7 = ":\\New Folder.exe" wide //weight: 5
        $x_5_8 = "OperationDefecha@yahoo.com" wide //weight: 5
        $x_5_9 = "CPQEASYBTTN" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 1 of ($x_11_*) and 6 of ($x_5_*))) or
            ((1 of ($x_100_*) and 1 of ($x_11_*) and 1 of ($x_10_*) and 4 of ($x_5_*))) or
            (all of ($x*))
        )
}

