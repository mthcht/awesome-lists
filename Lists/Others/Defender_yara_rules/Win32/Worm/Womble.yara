rule Worm_Win32_Womble_D_2147582734_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Womble.D"
        threat_id = "2147582734"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Womble"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "fastmail." ascii //weight: 1
        $x_1_2 = "graffiti." ascii //weight: 1
        $x_1_3 = ".com/current/" ascii //weight: 1
        $x_1_4 = "?a=%d&d=0:0:%d" ascii //weight: 1
        $x_1_5 = "<frame src=" ascii //weight: 1
        $x_1_6 = "Explorer\\Shell Folders" ascii //weight: 1
        $x_1_7 = "application/pdf" ascii //weight: 1
        $x_1_8 = "Internet Account Manager\\Accounts" ascii //weight: 1
        $x_1_9 = "Preference=" ascii //weight: 1
        $x_1_10 = "connect to server %s, %d" ascii //weight: 1
        $x_1_11 = "Look at this!" ascii //weight: 1
        $x_1_12 = "passwords.doc" ascii //weight: 1
        $x_1_13 = "_START_FILE_" ascii //weight: 1
        $x_1_14 = "_END_FILE_" ascii //weight: 1
        $x_1_15 = "_END_ADDRS_" ascii //weight: 1
        $x_1_16 = "HELO %s" ascii //weight: 1
        $x_1_17 = "User-Agent: Microsoft Outlook" ascii //weight: 1
        $x_1_18 = "Date: %s, %.2d %s %.4d" ascii //weight: 1
        $x_1_19 = "From: \"%s\" <%s>" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (14 of ($x*))
}

