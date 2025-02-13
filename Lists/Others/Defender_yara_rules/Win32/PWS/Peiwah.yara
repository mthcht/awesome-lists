rule PWS_Win32_Peiwah_A_2147600618_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Peiwah.A"
        threat_id = "2147600618"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Peiwah"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PS-Ware IE PS" ascii //weight: 1
        $x_1_2 = "Send User name && type" ascii //weight: 1
        $x_1_3 = "Disable RegEdit" ascii //weight: 1
        $x_1_4 = "Disable Task Manager" ascii //weight: 1
        $x_1_5 = "Disable MS-Config" ascii //weight: 1
        $x_1_6 = "Send Y!msgr Password" ascii //weight: 1
        $x_1_7 = "&Decoder" ascii //weight: 1
        $x_1_8 = "Server name" ascii //weight: 1
        $x_1_9 = "spoolsv.exe" ascii //weight: 1
        $x_1_10 = "ypager.exe" ascii //weight: 1
        $x_1_11 = "Song1.mp3.exe!" ascii //weight: 1
        $x_1_12 = "Fake message" ascii //weight: 1
        $x_1_13 = "Exclamation!" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (9 of ($x*))
}

