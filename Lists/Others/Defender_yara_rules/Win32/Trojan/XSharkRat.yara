rule Trojan_Win32_XSharkRat_PA_2147745221_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/XSharkRat.PA!MTB"
        threat_id = "2147745221"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "XSharkRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = "StubXShark.exe" ascii //weight: 5
        $x_5_2 = "ServerXShark" ascii //weight: 5
        $x_1_3 = "get_MachineName" ascii //weight: 1
        $x_1_4 = "get_OSFullName" ascii //weight: 1
        $x_1_5 = "get_UserName" ascii //weight: 1
        $x_1_6 = "secret=XSharked000" wide //weight: 1
        $x_1_7 = "/adduser.php" wide //weight: 1
        $x_1_8 = "/getusers.php" wide //weight: 1
        $x_1_9 = "/userInfo.php" wide //weight: 1
        $x_1_10 = "/Handler.php" wide //weight: 1
        $x_1_11 = "/command.bin" wide //weight: 1
        $x_1_12 = "/result.bin" wide //weight: 1
        $x_1_13 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 [0-37] 2e 00 30 00 30 00 30 00 77 00 65 00 62 00 68 00 6f 00 73 00 74 00 61 00 70 00 70 00 2e 00 63 00 6f 00 6d 00 2f 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

