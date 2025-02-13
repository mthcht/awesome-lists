rule HackTool_Win32_Panddos_A_2147612366_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Panddos.A"
        threat_id = "2147612366"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Panddos"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "32"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "%s\\NetBot.ini" ascii //weight: 10
        $x_10_2 = "NetBot Attacker" ascii //weight: 10
        $x_10_3 = "hackeroo.3322.org" ascii //weight: 10
        $x_10_4 = "www.hackeroo.com" ascii //weight: 10
        $x_10_5 = "NetBot.DDOS.Team" ascii //weight: 10
        $x_10_6 = "Panda DDos" ascii //weight: 10
        $x_10_7 = "www.nbddos.com/attack.txt" ascii //weight: 10
        $x_1_8 = "\\\\.\\SICE" ascii //weight: 1
        $x_1_9 = "\\\\.\\SIWVID" ascii //weight: 1
        $x_1_10 = "\\\\.\\NTICE" ascii //weight: 1
        $x_10_11 = {6e 65 74 20 6c 6f 63 61 6c 67 72 6f 75 70 20 61 64 6d 69 6e 69 73 74 72 61 74 6f 72 73 20 [0-10] 20 2f 61 64 64}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 2 of ($x_1_*))) or
            ((4 of ($x_10_*))) or
            (all of ($x*))
        )
}

