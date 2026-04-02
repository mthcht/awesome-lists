rule Trojan_Win32_Valleyrat_AMTB_2147959263_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Valleyrat!AMTB"
        threat_id = "2147959263"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Valleyrat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_7_1 = {8b 56 08 8b 45 14 8d 3c 11 8b 55 08 0f b6 04 02 99 bb c8 01 00 00 f7 fb ff 45 08 b8 cd cc cc cc 80 c2 36 30 17 f7 e1 c1 ea 03 8d 04 92 03 c0 8b d1 2b d0}  //weight: 7, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Valleyrat_AMTB_2147959263_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Valleyrat!AMTB"
        threat_id = "2147959263"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Valleyrat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%s\\Document\\_\\_\\_\\_\\_" ascii //weight: 1
        $x_1_2 = "_\\_\\_\\_\\document.bat" ascii //weight: 1
        $x_1_3 = "C:\\Users\\Administrator\\Desktop\\msimg32\\x64\\Release\\msimg32.pdb" ascii //weight: 1
        $x_1_4 = "D:\\Malware Project\\msimg32\\x64\\Release\\msimg32.pdb" ascii //weight: 1
        $x_1_5 = "msimg32.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

