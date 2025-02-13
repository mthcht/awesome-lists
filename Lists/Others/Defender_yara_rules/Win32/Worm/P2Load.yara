rule Worm_Win32_P2Load_D_2147603175_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/P2Load.D"
        threat_id = "2147603175"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "P2Load"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "http://juiillosks.sytes.net/" ascii //weight: 1
        $x_1_2 = "http://www.dutty.de/" ascii //weight: 1
        $x_1_3 = "Program Files\\Kazaa\\My Shared Folder" ascii //weight: 1
        $x_1_4 = "Program Files\\eMule\\Incoming" ascii //weight: 1
        $x_1_5 = "Software\\iMesh\\iMesh5\\Transfer" ascii //weight: 1
        $x_1_6 = {2f 64 61 74 61 2f 66 69 6c 65 [0-5] 2e 73 79 73}  //weight: 1, accuracy: Low
        $x_1_7 = "z:\\Programme\\Internet Explorer\\iexplore.exe \"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

