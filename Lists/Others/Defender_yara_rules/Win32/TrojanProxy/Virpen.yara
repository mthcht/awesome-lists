rule TrojanProxy_Win32_Virpen_A_2147655124_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Virpen.A"
        threat_id = "2147655124"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Virpen"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "&task=" ascii //weight: 1
        $x_1_2 = {13 41 64 64 50 6f 72 74 4e 75 6d 62 65 72 54 6f 48 6f 73 74}  //weight: 1, accuracy: High
        $x_1_3 = "ipvpnme.ru/logs/" ascii //weight: 1
        $x_1_4 = {68 49 76 45 00 8d 45 fc}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

