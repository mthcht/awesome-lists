rule TrojanProxy_Win32_Minigaway_A_2147641179_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Minigaway.A"
        threat_id = "2147641179"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Minigaway"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Gateway::CGateway3::" ascii //weight: 1
        $x_1_2 = "Gateway::CListen::" ascii //weight: 1
        $x_1_3 = "Gateway::CTunnel::" ascii //weight: 1
        $x_1_4 = "Gateway::CSocksUndefined::" ascii //weight: 1
        $x_1_5 = "/CallBack/SomeScripts/" ascii //weight: 1
        $x_1_6 = "/perl/scripts/errorMG.pl" ascii //weight: 1
        $x_1_7 = ".php?socks_id=%d&check25=%d" ascii //weight: 1
        $x_2_8 = {69 70 3a 70 6f 72 74 3d 25 73 3a 25 68 75 09 69 64 3d 25 6c 75 09 6c 69 73 74 65 6e 3d 25 68 75 09 6d 6f 64 3d 25 6c 75}  //weight: 2, accuracy: High
        $x_2_9 = {72 65 6c 3d 25 6c 75 25 25 09 6f 6e 6c 69 6e 65 3d 25 6c 75 09 72 65 63 6f 6e 6e 3d 25 6c 75}  //weight: 2, accuracy: High
        $x_2_10 = {61 74 2f 77 74 3d 25 6c 75 2f 25 6c 75 09 74 2f 73 3d 25 6c 75 2f 25 6c 75 09 75 72 65 63 2f 61 72 65 63 3d 25 6c 75 2f 25 6c 75 28 6d 73 65 63 29}  //weight: 2, accuracy: High
        $x_2_11 = {8b 45 f8 8d 3c 30 03 7b 04 8d 46 f4 e8 ?? ?? 00 00 66 8b 47 08 ff 45 f4 66 89 46 fc 8b 47 0c 89 06 8b 45 f4 83 c6 10 3b 03 72 d5}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 6 of ($x_1_*))) or
            ((3 of ($x_2_*) and 4 of ($x_1_*))) or
            ((4 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanProxy_Win32_Minigaway_B_2147642405_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Minigaway.B"
        threat_id = "2147642405"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Minigaway"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "GET /CallBack/SomeScripts/update25.php?socks_id=%d&check25=%d HTTP/1.0" ascii //weight: 4
        $x_3_2 = ".DEFAULT\\Software\\AMService\\CallBack" ascii //weight: 3
        $x_3_3 = " : fCreateTunnelWithClientSide == NULL" ascii //weight: 3
        $x_3_4 = "POST /CallBack/SomeScripts/mgsNewPeer.php HTTP/1.0" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

