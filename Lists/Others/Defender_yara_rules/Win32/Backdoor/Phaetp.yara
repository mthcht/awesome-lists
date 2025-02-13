rule Backdoor_Win32_Phaetp_B_2147815485_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Phaetp.B!dha"
        threat_id = "2147815485"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Phaetp"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko" wide //weight: 1
        $x_1_2 = "Loader" ascii //weight: 1
        $x_1_3 = {55 8b ec 81 ec 1c 01 00 00 56 68 24 31 00 10 8d 85 e4 fe ff ff 50 c6 45 ec 00 c6 45 e8 00 c7 05}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

