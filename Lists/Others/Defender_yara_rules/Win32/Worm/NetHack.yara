rule Worm_Win32_NetHack_A_2147600086_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/NetHack.A"
        threat_id = "2147600086"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "NetHack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "62"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {63 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 63 74 66 6d 6f 6e ?? 2e 65 78 65}  //weight: 10, accuracy: Low
        $x_10_2 = {53 65 6e 64 69 6e 67 20 70 61 79 6c 6f 61 64 ?? 2e 2e 2e 66 69 6e 69 73 68}  //weight: 10, accuracy: Low
        $x_10_3 = "4b324fc8-1670-01d3-1278-5a47bf6ee188" ascii //weight: 10
        $x_10_4 = "C:\\WINDOWS\\SYSTEM32\\tmipo.bat" ascii //weight: 10
        $x_10_5 = "net stop sharedaccess" ascii //weight: 10
        $x_10_6 = {53 65 74 20 78 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 74 29 0d 0a 78 2e 4f 70 65 6e 20 22 47 45 54 22 2c 20 72 2c 20 30 0d 0a 78 2e 53 65 6e 64 28 29 0d 0a 61 64 73 20 3d 20 22 41 44 4f 22 2b 22 44 42 2e 53 74 72 65 61 6d}  //weight: 10, accuracy: High
        $x_1_7 = "%s\\pipe\\BROWSER" ascii //weight: 1
        $x_1_8 = "f:\\source\\cg\\cgall\\ide_hackdriver\\objfre_wxp_x86\\i386\\pcidisk.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

